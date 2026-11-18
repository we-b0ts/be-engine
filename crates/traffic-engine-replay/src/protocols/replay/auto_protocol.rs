use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep, timeout};

use super::ReplayProtocol;
use crate::detection::{
    DetectedProtocol as DetectedClientProtocol, Detection as ClientProtocolDetection,
    detect_client_protocol_with,
};

const MAX_SNIFF_BYTES: usize = 4096;
const SNIFF_TIMEOUT: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_millis(5);

#[cfg(test)]
pub async fn detect(stream: &TcpStream) -> Result<Option<ReplayProtocol>> {
    detect_with_providers(stream, &crate::protocols::default_providers()).await
}

pub async fn detect_with_providers(
    stream: &TcpStream,
    providers: &crate::protocols::DependencyProviders,
) -> Result<Option<ReplayProtocol>> {
    let mut buffer = vec![0_u8; MAX_SNIFF_BYTES];
    let initial_len = stream.peek(&mut buffer).await?;
    if initial_len == 0 {
        return Ok(None);
    }
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("timed out identifying auto replay target protocol"));
        }
        let len = timeout(remaining, stream.peek(&mut buffer))
            .await
            .map_err(|_| anyhow!("timed out peeking auto replay target protocol"))??;
        let bytes = &buffer[..len];
        match detect_client_protocol_with(bytes, providers) {
            ClientProtocolDetection::Match(DetectedClientProtocol::Redis) => {
                return Ok(Some(ReplayProtocol::Redis));
            }
            ClientProtocolDetection::Match(DetectedClientProtocol::Http) => {
                return Ok(Some(ReplayProtocol::Http));
            }
            ClientProtocolDetection::Match(DetectedClientProtocol::Tls) => {
                return Ok(Some(ReplayProtocol::Https));
            }
            ClientProtocolDetection::Match(DetectedClientProtocol::Registered(protocol)) => {
                return Ok(Some(ReplayProtocol::registered(protocol)));
            }
            ClientProtocolDetection::NeedMore if len < MAX_SNIFF_BYTES => {
                sleep(RETRY_INTERVAL).await;
            }
            ClientProtocolDetection::NeedMore | ClientProtocolDetection::NoMatch => {
                return Err(anyhow!(
                    "auto replay target traffic is not a supported replay protocol"
                ));
            }
            ClientProtocolDetection::Match(protocol) => {
                return Err(anyhow!(
                    "auto replay target detected unsupported protocol {protocol:?}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[tokio::test]
    async fn detects_protocol_from_runtime_traffic() {
        for (payload, expected) in [
            (b"*1\r\n$4\r\nPING\r\n".as_slice(), ReplayProtocol::Redis),
            (
                b"GET /resource HTTP/1.1\r\nHost: api.example.test\r\n\r\n".as_slice(),
                ReplayProtocol::Http,
            ),
            (b"\x16\x03\x01\x00\x01".as_slice(), ReplayProtocol::Https),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            client.write_all(payload).await.unwrap();

            assert_eq!(detect(&server).await.unwrap(), Some(expected));
        }
    }

    #[tokio::test]
    async fn idle_before_first_byte_does_not_consume_protocol_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let detection = tokio::spawn(async move { detect(&server).await });

        tokio::time::sleep(SNIFF_TIMEOUT + Duration::from_millis(50)).await;
        client.write_all(b"*1\r\n$4\r\nPING\r\n").await.unwrap();

        assert_eq!(
            detection.await.unwrap().unwrap(),
            Some(ReplayProtocol::Redis)
        );
    }

    #[tokio::test]
    async fn eof_before_first_byte_is_a_clean_connection_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(client);

        assert_eq!(detect(&server).await.unwrap(), None);
    }
}
