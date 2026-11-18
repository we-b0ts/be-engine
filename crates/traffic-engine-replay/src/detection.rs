use crate::config::{TcpApplicationProtocol, TcpProtocolDetectionConfig};
use crate::protocols::{DependencyProtocol, DependencyProviders};
use traffic_protocol::{Peer, Probe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    Http,
    Tls,
    Redis,
    Registered(DependencyProtocol),
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    Match(DetectedProtocol),
    NeedMore,
    NoMatch,
}

pub fn protocol_override(
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
            TcpApplicationProtocol::Memcached => {
                DetectedProtocol::Registered(DependencyProtocol::new("memcached"))
            }
            TcpApplicationProtocol::Kafka => {
                DetectedProtocol::Registered(DependencyProtocol::new("kafka"))
            }
            TcpApplicationProtocol::Motan => {
                DetectedProtocol::Registered(DependencyProtocol::new("motan"))
            }
            TcpApplicationProtocol::Raw => DetectedProtocol::Raw,
        })
}

#[cfg(test)]
pub fn detect_client_protocol(bytes: &[u8]) -> Detection {
    detect_client_protocol_with(bytes, &crate::protocols::default_providers())
}

pub fn detect_client_protocol_with(bytes: &[u8], providers: &DependencyProviders) -> Detection {
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
    if incomplete {
        Detection::NeedMore
    } else {
        Detection::NoMatch
    }
}

pub fn detect_server_protocol_with(bytes: &[u8], providers: &DependencyProviders) -> Detection {
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
        DependencyProtocol::Redis => DetectedProtocol::Redis,
        _ => DetectedProtocol::Registered(protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_registered_client_protocols() {
        assert_eq!(
            detect_client_protocol(b"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"),
            Detection::Match(DetectedProtocol::Redis)
        );
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
    fn absent_protocol_implementations_have_no_native_recognition() {
        for bytes in [b"get key\r\n".as_slice(), &[0x80, 0x00], &[0xf1, 0xf1]] {
            assert_eq!(detect_client_protocol(bytes), Detection::NoMatch);
        }
    }

    #[test]
    fn fragmented_registered_commands_wait_for_their_native_prefix() {
        assert_eq!(
            detect_client_protocol(b"PROPFIND /items HTTP/1."),
            Detection::NeedMore
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
    }
}
