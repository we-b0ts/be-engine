use crate::config::{TcpApplicationProtocol, TcpProtocolDetectionConfig};
use crate::memcached::text_request_line_is_valid;

const MEMCACHED_BINARY_REQUEST_MAGIC: u8 = 0x80;
const MYSQL_HANDSHAKE_PROTOCOL_VERSION: u8 = 0x0a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectedProtocol {
    Http,
    Tls,
    Mysql,
    Redis,
    MemcachedText,
    MemcachedBinary,
    Kafka,
    Motan,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detection {
    Match(DetectedProtocol),
    NeedMore,
    NoMatch,
}

pub(crate) fn protocol_override(
    config: &TcpProtocolDetectionConfig,
    host: &str,
    port: u16,
) -> Option<DetectedProtocol> {
    config
        .overrides
        .iter()
        .find(|candidate| {
            candidate.port == port
                && candidate
                    .host
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(host.trim_end_matches('.'))
        })
        .map(|candidate| match candidate.protocol {
            TcpApplicationProtocol::Redis => DetectedProtocol::Redis,
            TcpApplicationProtocol::Memcached => DetectedProtocol::MemcachedText,
            TcpApplicationProtocol::Kafka => DetectedProtocol::Kafka,
            TcpApplicationProtocol::Motan => DetectedProtocol::Motan,
            TcpApplicationProtocol::Raw => DetectedProtocol::Raw,
        })
}

pub(crate) fn detect_client_protocol(bytes: &[u8]) -> Detection {
    if bytes.is_empty() {
        return Detection::NeedMore;
    }
    if bytes.starts_with(&[0xF1]) {
        return detect_motan(bytes);
    }
    if bytes[0] == MEMCACHED_BINARY_REQUEST_MAGIC {
        return detect_memcached_binary(bytes);
    }
    if bytes[0] == b'*' {
        return match redis_protocol::resp2::decode::decode(bytes) {
            Ok(Some((redis_protocol::resp2::types::OwnedFrame::Array(values), _)))
                if redis_array_is_command(&values) =>
            {
                Detection::Match(DetectedProtocol::Redis)
            }
            Ok(Some(_)) | Err(_) => Detection::NoMatch,
            Ok(None) => Detection::NeedMore,
        };
    }
    if bytes[0] == 0x16 {
        return if bytes.len() < 3 {
            Detection::NeedMore
        } else if bytes[1] == 0x03 && bytes[2] <= 0x04 {
            Detection::Match(DetectedProtocol::Tls)
        } else {
            Detection::NoMatch
        };
    }
    detect_text_protocol(bytes)
}

fn detect_motan(bytes: &[u8]) -> Detection {
    if bytes.len() < 2 {
        return Detection::NeedMore;
    }
    if bytes[..2] != [0xF1, 0xF1] {
        return Detection::NoMatch;
    }
    if bytes.len() < 18 {
        return Detection::NeedMore;
    }
    if bytes[16..18] == [0xF0, 0xF0] {
        Detection::Match(DetectedProtocol::Motan)
    } else {
        Detection::NoMatch
    }
}

fn redis_array_is_command(values: &[redis_protocol::resp2::types::OwnedFrame]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| {
            matches!(
                value,
                redis_protocol::resp2::types::OwnedFrame::BulkString(_)
                    | redis_protocol::resp2::types::OwnedFrame::SimpleString(_)
            )
        })
        && values.first().is_some_and(|value| match value {
            redis_protocol::resp2::types::OwnedFrame::BulkString(value)
            | redis_protocol::resp2::types::OwnedFrame::SimpleString(value) => {
                std::str::from_utf8(value).is_ok_and(|name| {
                    !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_graphic())
                })
            }
            _ => false,
        })
}

pub(crate) fn detect_mysql_server(bytes: &[u8]) -> Detection {
    if bytes.len() < 5 {
        return Detection::NeedMore;
    }
    if bytes[3] == 0 && bytes[4] == MYSQL_HANDSHAKE_PROTOCOL_VERSION {
        Detection::Match(DetectedProtocol::Mysql)
    } else {
        Detection::NoMatch
    }
}

fn detect_memcached_binary(bytes: &[u8]) -> Detection {
    if bytes.len() < 24 {
        return Detection::NeedMore;
    }
    let key_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let extras_len = bytes[4] as usize;
    let body_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    if extras_len + key_len > body_len {
        Detection::NoMatch
    } else {
        Detection::Match(DetectedProtocol::MemcachedBinary)
    }
}

fn detect_text_protocol(bytes: &[u8]) -> Detection {
    let Some(line_end) = bytes.windows(2).position(|window| window == b"\r\n") else {
        return if bytes.len() < 4096 && looks_like_known_text_prefix(bytes) {
            Detection::NeedMore
        } else {
            Detection::NoMatch
        };
    };
    let Ok(line) = std::str::from_utf8(&bytes[..line_end]) else {
        return Detection::NoMatch;
    };
    let tokens = line.split_ascii_whitespace().collect::<Vec<_>>();
    let Some(command) = tokens.first().map(|value| value.to_ascii_lowercase()) else {
        return Detection::NoMatch;
    };
    if is_http_request_line(&tokens) {
        return Detection::Match(DetectedProtocol::Http);
    }
    if tokens[0] == command && text_request_line_is_valid(&tokens, false) {
        Detection::Match(DetectedProtocol::MemcachedText)
    } else {
        Detection::NoMatch
    }
}

fn is_http_request_line(tokens: &[&str]) -> bool {
    tokens.len() == 3
        && matches!(
            tokens[0],
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        )
        && matches!(tokens[2], "HTTP/1.0" | "HTTP/1.1")
}

fn looks_like_known_text_prefix(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"get ",
        b"gets ",
        b"set ",
        b"add ",
        b"replace ",
        b"append ",
        b"prepend ",
        b"cas ",
        b"delete ",
        b"incr ",
        b"decr ",
        b"touch ",
        b"gat ",
        b"gats ",
        b"stats",
        b"version",
        b"flush_all",
        b"quit",
        b"verbosity ",
    ];
    PREFIXES
        .iter()
        .any(|prefix| prefix.starts_with(bytes) || bytes.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_strong_client_protocol_signatures() {
        assert_eq!(
            detect_client_protocol(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"),
            Detection::Match(DetectedProtocol::Redis)
        );
        let mut binary = vec![0_u8; 24];
        binary[0] = 0x80;
        assert_eq!(
            detect_client_protocol(&binary),
            Detection::Match(DetectedProtocol::MemcachedBinary)
        );
        assert_eq!(
            detect_client_protocol(b"get key\r\n"),
            Detection::Match(DetectedProtocol::MemcachedText)
        );
        let mut motan = vec![0_u8; 18];
        motan[..2].copy_from_slice(&[0xF1, 0xF1]);
        motan[16..18].copy_from_slice(&[0xF0, 0xF0]);
        assert_eq!(
            detect_client_protocol(&motan),
            Detection::Match(DetectedProtocol::Motan)
        );
    }

    #[test]
    fn distinguishes_http_from_memcached_text() {
        assert_eq!(
            detect_client_protocol(b"GET /items HTTP/1.1\r\n"),
            Detection::Match(DetectedProtocol::Http)
        );
        assert_eq!(
            detect_client_protocol(b"GET /items\r\n"),
            Detection::NoMatch
        );
    }

    #[test]
    fn incomplete_signatures_need_more_data() {
        assert_eq!(
            detect_client_protocol(b"*2\r\n$3\r\nGE"),
            Detection::NeedMore
        );
        assert_eq!(detect_client_protocol(&[0x80, 0x00]), Detection::NeedMore);
        assert_eq!(detect_client_protocol(b"set key 0"), Detection::NeedMore);
    }

    #[test]
    fn fragmented_redis_and_storage_commands_stay_undecided_until_complete() {
        let redis = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        for end in 1..redis.len() {
            assert_eq!(detect_client_protocol(&redis[..end]), Detection::NeedMore);
        }
        assert_eq!(
            detect_client_protocol(redis),
            Detection::Match(DetectedProtocol::Redis)
        );

        assert_eq!(detect_client_protocol(b"set key 0 60"), Detection::NeedMore);
        assert_eq!(
            detect_client_protocol(b"set key 0 60 5\r\nhello\r\n"),
            Detection::Match(DetectedProtocol::MemcachedText)
        );
    }
}
