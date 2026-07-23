use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const CLIENT_SSL: u32 = 0x0000_0800;
pub const CLIENT_COMPRESS: u32 = 0x0000_0020;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysqlPacket {
    pub sequence_id: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub capability_flags: u32,
    pub tls_requested: bool,
    pub username: Option<String>,
    pub database: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCommand {
    pub command_name: String,
    pub query: Option<String>,
}

impl ClientCommand {
    pub fn expects_server_response(&self) -> bool {
        !is_no_response_command(&self.command_name)
    }
}

pub fn is_no_response_command(command_name: &str) -> bool {
    matches!(
        command_name,
        "COM_QUIT" | "COM_STMT_CLOSE" | "COM_UNKNOWN_0x19"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPacketInfo {
    pub kind: String,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
}

impl MysqlPacket {
    pub fn encoded_len(&self) -> usize {
        4 + self.payload.len()
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let len = self.payload.len();
        let mut out = Vec::with_capacity(4 + len);
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(self.sequence_id);
        out.extend_from_slice(&self.payload);
        out
    }
}

pub(crate) fn readonly_error_packet(sequence_id: u8) -> MysqlPacket {
    let mut payload = Vec::new();
    payload.push(0xff);
    payload.extend_from_slice(&1290_u16.to_le_bytes());
    payload.extend_from_slice(b"#HY000");
    payload.extend_from_slice(b"request blocked by recording access policy");
    MysqlPacket {
        sequence_id,
        payload,
    }
}

pub async fn read_packet<R>(reader: &mut R) -> io::Result<Option<MysqlPacket>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }

    let len = header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some(MysqlPacket {
        sequence_id: header[3],
        payload,
    }))
}

pub fn parse_handshake_response(packet: &MysqlPacket) -> HandshakeResponse {
    let capability_flags = read_u32_le(&packet.payload, 0).unwrap_or_default();
    let tls_requested = capability_flags & CLIENT_SSL != 0;

    let mut username = None;
    let mut database = None;
    if packet.payload.len() > 32 && !tls_requested {
        let mut offset = 32;
        if let Some((value, next)) = read_null_string(&packet.payload, offset) {
            username = Some(value);
            offset = next;
        }

        if capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            if let Some((len, next)) = read_lenenc_int(&packet.payload, offset) {
                offset = next.saturating_add(len as usize).min(packet.payload.len());
            }
        } else if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
            if let Some(len) = packet.payload.get(offset).copied() {
                offset = offset
                    .saturating_add(1 + len as usize)
                    .min(packet.payload.len());
            }
        } else if let Some((_, next)) = read_null_string(&packet.payload, offset) {
            offset = next;
        }

        if capability_flags & CLIENT_CONNECT_WITH_DB != 0
            && let Some((value, _)) = read_null_string(&packet.payload, offset)
        {
            database = Some(value);
        }
    }

    HandshakeResponse {
        capability_flags,
        tls_requested,
        username,
        database,
    }
}

pub fn clear_client_compression_capability(packet: &mut MysqlPacket) -> bool {
    let Some(capability_flags) = read_u32_le(&packet.payload, 0) else {
        return false;
    };
    if capability_flags & CLIENT_COMPRESS == 0 {
        return false;
    }

    packet.payload[0..4].copy_from_slice(&(capability_flags & !CLIENT_COMPRESS).to_le_bytes());
    true
}

pub fn clear_server_compression_capability(packet: &mut MysqlPacket) -> bool {
    let Some(offset) = server_lower_capability_flags_offset(&packet.payload) else {
        return false;
    };
    let Some(lower_flags) = read_u16_le(&packet.payload, offset) else {
        return false;
    };
    let compression_flag = CLIENT_COMPRESS as u16;
    if lower_flags & compression_flag == 0 {
        return false;
    }

    packet.payload[offset..offset + 2]
        .copy_from_slice(&(lower_flags & !compression_flag).to_le_bytes());
    true
}

pub fn parse_client_command(packet: &MysqlPacket) -> Option<ClientCommand> {
    let command = *packet.payload.first()?;
    let rest = &packet.payload[1..];
    Some(match command {
        0x01 => ClientCommand {
            command_name: "COM_QUIT".to_string(),
            query: None,
        },
        0x02 => ClientCommand {
            command_name: "COM_INIT_DB".to_string(),
            query: Some(String::from_utf8_lossy(rest).to_string()),
        },
        0x03 => ClientCommand {
            command_name: "COM_QUERY".to_string(),
            query: Some(String::from_utf8_lossy(rest).to_string()),
        },
        0x0e => ClientCommand {
            command_name: "COM_PING".to_string(),
            query: None,
        },
        0x16 => ClientCommand {
            command_name: "COM_STMT_PREPARE".to_string(),
            query: Some(String::from_utf8_lossy(rest).to_string()),
        },
        0x17 => ClientCommand {
            command_name: "COM_STMT_EXECUTE".to_string(),
            query: None,
        },
        0x19 => ClientCommand {
            command_name: "COM_STMT_CLOSE".to_string(),
            query: None,
        },
        other => ClientCommand {
            command_name: format!("COM_UNKNOWN_{other:#04x}"),
            query: None,
        },
    })
}

pub fn parse_server_packet(packet: &MysqlPacket) -> ServerPacketInfo {
    match packet.payload.first().copied() {
        Some(0x00) => ServerPacketInfo {
            kind: "ok".to_string(),
            error_code: None,
            error_message: None,
        },
        Some(0xff) => {
            let code = read_u16_le(&packet.payload, 1);
            let message_start = if packet.payload.get(3) == Some(&b'#') {
                9
            } else {
                3
            };
            ServerPacketInfo {
                kind: "error".to_string(),
                error_code: code,
                error_message: (packet.payload.len() > message_start)
                    .then(|| String::from_utf8_lossy(&packet.payload[message_start..]).to_string()),
            }
        }
        Some(0xfe) if packet.payload.len() < 9 => ServerPacketInfo {
            kind: "eof".to_string(),
            error_code: None,
            error_message: None,
        },
        Some(_) => ServerPacketInfo {
            kind: "result_or_data".to_string(),
            error_code: None,
            error_message: None,
        },
        None => ServerPacketInfo {
            kind: "empty".to_string(),
            error_code: None,
            error_message: None,
        },
    }
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn server_lower_capability_flags_offset(payload: &[u8]) -> Option<usize> {
    if payload.first() != Some(&0x0a) {
        return None;
    }
    let server_version_len = payload.get(1..)?.iter().position(|byte| *byte == 0)? + 1;
    let offset = 1 + server_version_len + 4 + 8 + 1;
    payload.get(offset..offset + 2)?;
    Some(offset)
}

fn read_null_string(bytes: &[u8], offset: usize) -> Option<(String, usize)> {
    let rest = bytes.get(offset..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    let value = String::from_utf8_lossy(&rest[..end]).to_string();
    Some((value, offset + end + 1))
}

fn read_lenenc_int(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    match first {
        0xfc => Some((read_u16_le(bytes, offset + 1)? as u64, offset + 3)),
        0xfd => {
            let b1 = *bytes.get(offset + 1)? as u64;
            let b2 = *bytes.get(offset + 2)? as u64;
            let b3 = *bytes.get(offset + 3)? as u64;
            Some((b1 | (b2 << 8) | (b3 << 16), offset + 4))
        }
        0xfe => {
            let mut buf = [0_u8; 8];
            buf.copy_from_slice(bytes.get(offset + 1..offset + 9)?);
            Some((u64::from_le_bytes(buf), offset + 9))
        }
        value => Some((value as u64, offset + 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tls_request_from_capability_flags() {
        let mut payload = vec![0_u8; 32];
        payload[0..4].copy_from_slice(&(CLIENT_SSL | CLIENT_SECURE_CONNECTION).to_le_bytes());
        let packet = MysqlPacket {
            sequence_id: 1,
            payload,
        };
        let parsed = parse_handshake_response(&packet);
        assert!(parsed.tls_requested);
        assert_eq!(
            parsed.capability_flags,
            CLIENT_SSL | CLIENT_SECURE_CONNECTION
        );
    }

    #[test]
    fn parses_login_user_and_database_without_auth_bytes() {
        let flags = CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
        let mut payload = vec![0_u8; 32];
        payload[0..4].copy_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(b"alice\0");
        payload.push(4);
        payload.extend_from_slice(b"pass");
        payload.extend_from_slice(b"appdb\0");
        let packet = MysqlPacket {
            sequence_id: 1,
            payload,
        };

        let parsed = parse_handshake_response(&packet);
        assert_eq!(parsed.username.as_deref(), Some("alice"));
        assert_eq!(parsed.database.as_deref(), Some("appdb"));
    }

    #[test]
    fn clears_compression_from_client_handshake_response() {
        let expected_flags = CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
        let mut packet = MysqlPacket {
            sequence_id: 1,
            payload: {
                let mut payload = vec![0_u8; 32];
                payload[0..4].copy_from_slice(&(expected_flags | CLIENT_COMPRESS).to_le_bytes());
                payload
            },
        };

        assert!(clear_client_compression_capability(&mut packet));
        assert_eq!(
            parse_handshake_response(&packet).capability_flags,
            expected_flags
        );
        assert!(!clear_client_compression_capability(&mut packet));
    }

    #[test]
    fn clears_compression_from_protocol_v10_server_handshake() {
        let expected_flags = CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
        let mut packet = MysqlPacket {
            sequence_id: 0,
            payload: server_handshake_payload(expected_flags | CLIENT_COMPRESS),
        };
        let offset = server_lower_capability_flags_offset(&packet.payload).unwrap();

        assert!(clear_server_compression_capability(&mut packet));
        assert_eq!(
            read_u16_le(&packet.payload, offset).unwrap(),
            expected_flags as u16
        );
        assert!(!clear_server_compression_capability(&mut packet));
    }

    #[test]
    fn leaves_unrecognized_server_handshake_unchanged() {
        let mut packet = MysqlPacket {
            sequence_id: 0,
            payload: vec![0x09, 0x20, 0x00],
        };
        let original = packet.clone();

        assert!(!clear_server_compression_capability(&mut packet));
        assert_eq!(packet, original);
    }

    #[test]
    fn parses_query_command() {
        let packet = MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x03], b"select 1".to_vec()].concat(),
        };
        let command = parse_client_command(&packet).unwrap();
        assert_eq!(command.command_name, "COM_QUERY");
        assert_eq!(command.query.as_deref(), Some("select 1"));
        assert!(command.expects_server_response());
    }

    #[test]
    fn parses_stmt_close_as_no_response_command() {
        let packet = MysqlPacket {
            sequence_id: 0,
            payload: [vec![0x19], 42_u32.to_le_bytes().to_vec()].concat(),
        };
        let command = parse_client_command(&packet).unwrap();
        assert_eq!(command.command_name, "COM_STMT_CLOSE");
        assert_eq!(command.query, None);
        assert!(!command.expects_server_response());
    }

    #[test]
    fn builds_native_readonly_error_packet() {
        let packet = readonly_error_packet(7);
        assert_eq!(packet.sequence_id, 7);
        assert_eq!(packet.payload[0], 0xff);
        assert_eq!(
            u16::from_le_bytes([packet.payload[1], packet.payload[2]]),
            1290
        );
        assert!(packet.payload.windows(5).any(|window| window == b"HY000"));
    }

    fn server_handshake_payload(capability_flags: u32) -> Vec<u8> {
        let mut payload = vec![0x0a];
        payload.extend_from_slice(b"8.0.0-test\0");
        payload.extend_from_slice(&42_u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0);
        payload.extend_from_slice(&(capability_flags as u16).to_le_bytes());
        payload.push(0x21);
        payload.extend_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&((capability_flags >> 16) as u16).to_le_bytes());
        payload
    }
}
