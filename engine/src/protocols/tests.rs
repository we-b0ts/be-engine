use super::*;
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::Ordering;
pub use traffic_engine_evidence::protocols::test_support::*;
#[tokio::test]
async fn injected_redis_decoder_is_reused_across_one_hundred_thousand_frames() {
    let (providers, counts) = counted_providers();
    let session = redis_session(&providers).unwrap();
    let wire = b"+OK\r\n".repeat(100_000);
    let mut reader =
        traffic_protocol_redis::BufferedReader::with_session(wire.as_slice(), 8192, session);
    let started = std::time::Instant::now();
    for _ in 0..100_000 {
        let frame = traffic_protocol_redis::read_frame(&mut reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.raw.as_ref(), b"+OK\r\n");
    }
    assert!(
        traffic_protocol_redis::read_frame(&mut reader)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(counts.redis.sessions.load(Ordering::Relaxed), 1);
    assert_eq!(counts.redis.native_calls.load(Ordering::Relaxed), 100_000);
    eprintln!(
        "100000 injected Redis frames decoded in {:?}",
        started.elapsed()
    );
}

#[test]
fn instance_recognition_uses_replaced_providers_for_complete_and_partial_requests() {
    struct RejectingProvider(Arc<dyn DependencyProvider>);
    impl DependencyProvider for RejectingProvider {
        fn name(&self) -> &'static str {
            self.0.name()
        }
        fn recognize(&self, _probe: Probe<'_>) -> Recognition {
            Recognition::Reject
        }
        fn create_session(&self) -> Result<Session> {
            self.0.create_session()
        }
    }
    let original = default_providers();
    let mut customized = original.as_ref().clone();
    for kind in [DependencyProtocol::Http, DependencyProtocol::Redis] {
        customized
            .replace(
                kind,
                Arc::new(RejectingProvider(original.provider(kind).unwrap().clone())),
            )
            .unwrap();
    }
    for wire in [
        b"GET / HTTP/1.1\r\n".as_slice(),
        b"GET /",
        b"*1\r\n$4\r\nPING\r\n",
    ] {
        assert_eq!(
            crate::tcp_gateway::detect_client_protocol_with(wire, &customized),
            crate::tcp_gateway::ClientProtocolDetection::NoMatch,
        );
    }
    assert!(matches!(
        crate::tcp_gateway::detect_client_protocol_with(b"GET / HTTP/1.1\r\n", &original),
        crate::tcp_gateway::ClientProtocolDetection::Match(_),
    ));
}
