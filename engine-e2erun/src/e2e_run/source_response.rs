//! Source response location and timing metadata; response contents stay in assertions.
use std::{fs::File, io::BufReader, path::Path, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;

pub(super) fn path(case_dir: &Path) -> PathBuf {
    let canonical = case_dir.join("expected-response.json");
    if canonical.is_file() {
        canonical
    } else {
        case_dir.join("expected_response.json")
    }
}

pub(super) fn request_timeout(case_dir: &Path, execution_allowance: Duration) -> Result<Duration> {
    #[derive(Deserialize)]
    struct Timing {
        #[serde(default)]
        duration_ms: Option<u64>,
    }

    let file = File::open(path(case_dir)).context("failed to open Source response timing")?;
    // Deserialize only elapsed time. Status, headers and body are ignored and
    // never become request bytes or target inputs.
    let timing: Timing = serde_json::from_reader(BufReader::new(file))
        .context("invalid Source response timing metadata")?;
    execution_allowance
        .checked_add(Duration::from_millis(timing.duration_ms.unwrap_or(0)))
        .context("Source response timing exceeds the HTTP request budget range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpListener};

    #[test]
    fn timing_does_not_depend_on_response_contents_and_preserves_original_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let file = path(temp.path());
        for response in [
            r#"{"duration_ms":30262,"status":200,"body":{"data":"source-only"}}"#,
            r#"{"duration_ms":30262,"status":500,"body":null,"headers":{"x-test":"other"}}"#,
        ] {
            std::fs::write(&file, response).unwrap();
            assert_eq!(
                request_timeout(temp.path(), Duration::from_secs(30)).unwrap(),
                Duration::from_millis(60262)
            );
            assert_eq!(std::fs::read_to_string(&file).unwrap(), response);
        }
    }

    #[test]
    fn absent_timing_retains_the_allowance_and_invalid_timing_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("expected-response.json");
        std::fs::write(&file, "{}").unwrap();
        let allowance = Duration::from_secs(30);
        assert_eq!(request_timeout(temp.path(), allowance).unwrap(), allowance);
        for value in ["-1", "1.5", "\"30262\"", "18446744073709551616"] {
            std::fs::write(&file, format!("{{\"duration_ms\":{value}}}")).unwrap();
            assert!(request_timeout(temp.path(), allowance).is_err());
        }
    }

    #[tokio::test]
    async fn recorded_wait_can_outlive_the_allowance_without_supplying_response_data_to_target() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("expected-response.json"),
            r#"{"duration_ms":2000,"status":418,"body":{"data":"oracle-only"}}"#,
        )
        .unwrap();
        let timeout = request_timeout(temp.path(), Duration::from_millis(50)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|value| value == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(request.starts_with(b"GET /actual-request HTTP/1.1\r\n"));
            assert!(!request.windows(11).any(|value| value == b"oracle-only"));
            tokio::time::sleep(Duration::from_millis(250)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let response = crate::recorded_request::RecordedHttpClient::new(
            format!("http://{address}"),
            timeout,
            1024,
        )
        .send_bytes(
            br#"{"method":"GET","uri":"/actual-request","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}}"#,
            "recorded request",
        )
        .await
        .unwrap();
        assert_eq!(response.status.as_u16(), 200);
        assert_eq!(response.body.as_ref(), b"ok");
        server.await.unwrap();
    }
}
