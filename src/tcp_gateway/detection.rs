use crate::config::{TcpApplicationProtocol, TcpProtocolDetectionConfig};
use crate::memcached::text_request_line_is_valid;
use crate::protocols::{DependencyProtocol, DependencyProviders};
use traffic_protocol::{Peer, Probe};

const MEMCACHED_BINARY_REQUEST_MAGIC: u8 = 0x80;

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

#[cfg(test)]
pub(crate) fn detect_client_protocol(bytes: &[u8]) -> Detection {
    detect_client_protocol_with(bytes, &crate::protocols::default_providers())
}

pub(crate) fn detect_client_protocol_with(
    bytes: &[u8],
    providers: &DependencyProviders,
) -> Detection {
    let recognition = providers.recognize(Probe {
        peer: Peer::Client,
        bytes,
    });
    let incomplete = matches!(recognition, Ok(traffic_protocol::Detection::NeedMore));
    match recognition {
        Ok(traffic_protocol::Detection::Match(protocol)) => {
            return Detection::Match(native_protocol(protocol));
        }
        Err(error) => {
            tracing::warn!(%error, "dependency protocol recognition failed");
            return Detection::NoMatch;
        }
        _ => (),
    }
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
        return if incomplete {
            Detection::NeedMore
        } else {
            Detection::NoMatch
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
    match detect_text_protocol(bytes) {
        Detection::NoMatch if incomplete => Detection::NeedMore,
        detection => detection,
    }
}

fn detect_motan(bytes: &[u8]) -> Detection {
    match motan_protocol::inspect_protocol_version(bytes) {
        Ok(Some(_)) => Detection::Match(DetectedProtocol::Motan),
        Ok(None) => Detection::NeedMore,
        Err(_) => Detection::NoMatch,
    }
}

pub(crate) fn detect_mysql_server_with(bytes: &[u8], providers: &DependencyProviders) -> Detection {
    match providers.recognize(Probe {
        peer: Peer::Server,
        bytes,
    }) {
        Ok(traffic_protocol::Detection::Match(protocol)) => {
            Detection::Match(native_protocol(protocol))
        }
        Ok(traffic_protocol::Detection::NeedMore) => Detection::NeedMore,
        _ => Detection::NoMatch,
    }
}

fn native_protocol(protocol: DependencyProtocol) -> DetectedProtocol {
    match protocol {
        DependencyProtocol::Http => DetectedProtocol::Http,
        DependencyProtocol::Mysql => DetectedProtocol::Mysql,
        DependencyProtocol::Redis => DetectedProtocol::Redis,
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
    if tokens[0] == command && text_request_line_is_valid(&tokens, false) {
        Detection::Match(DetectedProtocol::MemcachedText)
    } else {
        Detection::NoMatch
    }
}

fn looks_like_known_text_prefix(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
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
        let motan2 = motan_protocol::FrameBuilder::request(1).encode().unwrap();
        assert_eq!(
            detect_client_protocol(&motan2[..13]),
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
    fn fragmented_commands_wait_only_for_their_recognition_prefix() {
        assert_eq!(
            detect_client_protocol(b"PROPFIND /items HTTP/1."),
            Detection::NeedMore
        );
        assert_eq!(
            detect_client_protocol(b"PROPFIND /items HTTP/1.1\r\n"),
            Detection::Match(DetectedProtocol::Http)
        );
        let redis = b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        let command_prefix = b"*2\r\n$3\r\nGET\r\n".len();
        for end in 1..command_prefix {
            assert_eq!(detect_client_protocol(&redis[..end]), Detection::NeedMore);
        }
        for end in command_prefix..=redis.len() {
            assert_eq!(
                detect_client_protocol(&redis[..end]),
                Detection::Match(DetectedProtocol::Redis)
            );
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
