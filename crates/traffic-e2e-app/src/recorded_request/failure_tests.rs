//! Dependency rejection interrupts ordinary HTTP independently of a business 5xx.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn unmatched_dependency_interrupts_http_before_business_returns_a_status() {
    for observed in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (failure, receiver) = tokio::sync::watch::channel(false);
        let target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            if observed {
                stream
                    .write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 100\r\n\r\nx",
                    )
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            failure.send(true).unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let client = RecordedHttpClient::new(origin, Duration::from_secs(900), 1024)
            .with_execution_failure(Some(receiver));
        let request=br#"{"method":"GET","uri":"/example","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}}"#;
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            client.send_bytes(request, "request.json"),
        )
        .await
        .unwrap()
        .err()
        .expect("engine must interrupt the request");
        let failure = error
            .downcast_ref::<crate::dependency::execution::UnmatchedDependency>()
            .unwrap();
        assert_eq!(failure.observed_status, observed.then_some(500));
        target.abort();
    }
}
