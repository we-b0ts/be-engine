use anyhow::{Result, anyhow};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep, timeout};

use super::ReplayProtocol;
use crate::tcp_gateway::{ClientProtocolDetection, DetectedClientProtocol, detect_client_protocol};

const MAX_SNIFF_BYTES: usize = 4096;
const SNIFF_TIMEOUT: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_millis(5);

pub(super) async fn detect(stream: &TcpStream) -> Result<ReplayProtocol> {
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut buffer = vec![0_u8; MAX_SNIFF_BYTES];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("timed out identifying auto replay target protocol"));
        }
        let len = timeout(remaining, stream.peek(&mut buffer))
            .await
            .map_err(|_| anyhow!("timed out peeking auto replay target protocol"))??;
        let bytes = &buffer[..len];
        match detect_client_protocol(bytes) {
            ClientProtocolDetection::Match(DetectedClientProtocol::Redis) => {
                return Ok(ReplayProtocol::Redis);
            }
            ClientProtocolDetection::Match(
                DetectedClientProtocol::MemcachedText | DetectedClientProtocol::MemcachedBinary,
            ) => return Ok(ReplayProtocol::Memcached),
            ClientProtocolDetection::NeedMore if len < MAX_SNIFF_BYTES => {
                sleep(RETRY_INTERVAL).await;
            }
            ClientProtocolDetection::NeedMore if bytes.first() == Some(&b'*') => {
                return Ok(ReplayProtocol::Redis);
            }
            ClientProtocolDetection::NeedMore | ClientProtocolDetection::NoMatch => {
                return Err(anyhow!(
                    "auto replay target traffic is neither Redis nor Memcached"
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
            (b"get key\r\n".as_slice(), ReplayProtocol::Memcached),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            client.write_all(payload).await.unwrap();

            assert_eq!(detect(&server).await.unwrap(), expected);
        }
    }
}
