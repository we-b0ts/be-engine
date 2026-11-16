//! Classic greeting and CLIENT_SSL upgrade followed by finite native requests.
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use anyhow::{Context, Result, ensure};
use tokio::io::AsyncBufReadExt;
use traffic_protocol::connection::{
    ConnectionInfo, ConnectionIo, NativeFuture, RequestHost, ResponseFramer, ServerSession,
};
use traffic_protocol::output::OutputStream;

use super::response::ResponseMessage;
use crate::{
    MysqlPacket, message::RequestMessage, model::ResultRowEncoding, types::SERVER_STATUS_AUTOCOMMIT,
};

pub(super) struct Server(pub ConnectionInfo);
static CONNECTION_ID: AtomicU32 = AtomicU32::new(1);

impl ServerSession for Server {
    fn run(
        self: Box<Self>,
        mut io: Box<dyn ConnectionIo>,
        host: Arc<dyn RequestHost>,
    ) -> NativeFuture<'static, ()> {
        Box::pin(async move {
            crate::write_packet(
                io.as_mut(),
                &crate::response::handshake_packet(CONNECTION_ID.fetch_add(1, Ordering::Relaxed)),
            )
            .await?;
            let mut login = read(io.as_mut(), self.0.max_frame_bytes)
                .await?
                .context("MySQL login missing")?;
            ensure!(
                login.sequence_id == 1 && login.payload.len() >= 32,
                "invalid MySQL login"
            );
            let mut identity = crate::parse_handshake_response(&login);
            if identity.tls_requested {
                ensure!(
                    login.payload.len() == 32,
                    "MySQL SSLRequest has an invalid size"
                );
                io = host.accept_tls(io, Vec::new()).await?;
                login = read(io.as_mut(), self.0.max_frame_bytes)
                    .await?
                    .context("MySQL TLS login missing")?;
                ensure!(
                    login.sequence_id == 2 && login.payload.len() > 32,
                    "invalid MySQL TLS login"
                );
                identity = crate::parse_handshake_response(&login);
            }
            ensure!(
                login.payload.len() > 32 && identity.username.is_some(),
                "invalid MySQL login identity"
            );
            ensure!(
                identity.capability_flags & crate::CLIENT_COMPRESS == 0,
                "MySQL compression is unavailable"
            );
            crate::write_packet(
                io.as_mut(),
                &MysqlPacket {
                    sequence_id: login.sequence_id.wrapping_add(1),
                    payload: crate::response::ok_payload(0, 0),
                },
            )
            .await?;
            let mut status = SERVER_STATUS_AUTOCOMMIT;
            let mut io = tokio::io::BufReader::new(io);
            while !io.fill_buf().await?.is_empty() {
                let _input = host.begin_input().await?;
                let packet = read(&mut io, self.0.max_frame_bytes)
                    .await?
                    .context("MySQL command ended before its frame")?;
                ensure!(
                    packet.sequence_id == 0,
                    "MySQL command sequence must begin at zero"
                );
                let command =
                    crate::parse_client_command(&packet).context("empty MySQL command")?;
                if command.command_name == "COM_QUIT" {
                    break;
                }
                let mut framer = Framer {
                    status,
                    sql: command.query.clone().unwrap_or_default(),
                    successful: false,
                };
                if command.command_name == "COM_PING" {
                    crate::write_packet(
                        &mut io,
                        &MysqlPacket {
                            sequence_id: 1,
                            payload: crate::response::ok_payload_with_status(0, 0, status),
                        },
                    )
                    .await?;
                    continue;
                }
                ensure!(
                    matches!(command.command_name.as_str(), "COM_QUERY" | "COM_INIT_DB"),
                    "unsupported MySQL command {}",
                    command.command_name
                );
                if let Some(response) = session_response(
                    &command.command_name,
                    command.query.as_deref(),
                    identity.database.as_deref(),
                ) {
                    let mut output =
                        crate::output::response(&response, ResultRowEncoding::Text, status);
                    traffic_replay::output::deliver(&mut io, &mut output, None).await?;
                    continue;
                }
                let request = RequestMessage {
                    command: command.command_name.clone(),
                    sql: command.query.clone(),
                    params: None,
                    database: identity.database.clone(),
                    username: identity.username.clone(),
                };
                let delivery = host.execute(Arc::new(request)).await?;
                delivery.write(&mut io, &mut framer).await?;
                status = framer.status;
                if command.command_name == "COM_INIT_DB" && framer.successful {
                    identity.database = command.query;
                }
            }
            Ok(())
        })
    }
}

fn session_response(
    command: &str,
    sql: Option<&str>,
    database: Option<&str>,
) -> Option<crate::recorded::RecordedMysqlResponse> {
    if command != "COM_QUERY" {
        return None;
    }
    let sql = sql?;
    if crate::maintenance::is_mysql_maintenance_exchange(command, Some(sql))
        || crate::session_setup::is_mysql_session_setup_sql(sql)
    {
        crate::builtin::builtin_response(sql, database)
    } else {
        None
    }
}

struct Framer {
    status: u16,
    sql: String,
    successful: bool,
}
impl ResponseFramer for Framer {
    fn prepare_output(
        &mut self,
        mut output: Box<dyn OutputStream>,
    ) -> Result<Box<dyn OutputStream>> {
        use traffic_protocol::output::OutputBoundary;
        let chunk = output
            .next()?
            .context("MySQL response envelope is absent")?;
        ensure!(
            output.part_count() == 0
                && chunk.boundary == OutputBoundary::End
                && chunk.complete
                && output.next()?.is_none(),
            "MySQL response envelope has unexpected output boundaries"
        );
        let envelope: ResponseMessage = serde_json::from_slice(&chunk.bytes)?;
        if matches!(envelope.response.status.as_str(), "ok" | "resultset") {
            self.successful = true;
            self.status = crate::session_status::after_response(
                self.status,
                &self.sql,
                envelope.response.server_status,
                envelope.source_status_before,
            );
        }
        envelope.into_output(self.status)
    }
}

async fn read(io: &mut dyn ConnectionIo, limit: usize) -> Result<Option<MysqlPacket>> {
    use tokio::io::AsyncReadExt;
    let mut header = [0; 4];
    if io.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    io.read_exact(&mut header[1..]).await?;
    let mut payload = Vec::new();
    let sequence_id = header[3];
    let mut sequence = sequence_id;
    loop {
        let size =
            usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16);
        ensure!(
            header[3] == sequence,
            "MySQL continuation sequence mismatch"
        );
        ensure!(
            size <= limit.saturating_sub(payload.len()),
            "MySQL request exceeds frame limit"
        );
        let offset = payload.len();
        payload.resize(offset + size, 0);
        io.read_exact(&mut payload[offset..]).await?;
        if size < crate::continuation::MAX_PACKET_PAYLOAD_LEN {
            return Ok(Some(MysqlPacket {
                sequence_id,
                payload,
            }));
        }
        sequence = sequence.wrapping_add(1);
        io.read_exact(&mut header).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traffic_protocol::{
        message::{MessageEncoder, ProtocolMessage},
        output::OutputBoundary,
    };

    #[test]
    fn session_output_preserves_headers_rows_and_end_for_shared_delivery() {
        let response = ResponseMessage::new(
            serde_json::from_value(serde_json::json!({
                "status":"resultset",
                "columns":[{"name":"fixture","family":"integer","sql_type":"INT"}],
                "rows":[[{"kind":"integer","value":7}]]
            }))
            .unwrap(),
            None,
        )
        .unwrap();
        let values = response
            .project()
            .unwrap()
            .values
            .into_iter()
            .map(|(path, value)| (path, value.bytes))
            .collect();
        let mut framer = Framer {
            status: SERVER_STATUS_AUTOCOMMIT,
            sql: "SELECT 7 AS fixture".into(),
            successful: false,
        };
        let mut output = framer
            .prepare_output(response.output(&values).unwrap())
            .unwrap();
        assert!(framer.successful);
        assert_eq!(output.part_count(), 1);
        let mut boundaries = Vec::new();
        while let Some(chunk) = output.next().unwrap() {
            if chunk.complete {
                boundaries.push(chunk.boundary);
            }
        }
        assert_eq!(
            boundaries,
            [
                OutputBoundary::Headers,
                OutputBoundary::Part,
                OutputBoundary::End
            ]
        );
    }
}
