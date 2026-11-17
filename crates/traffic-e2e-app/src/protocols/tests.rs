use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
pub(crate) struct Stats {
    pub(crate) sessions: AtomicUsize,
    pub(crate) native_calls: AtomicUsize,
}

#[derive(Default)]
pub(crate) struct Counts {
    pub(crate) http: Arc<Stats>,
    pub(crate) mysql: Arc<Stats>,
    pub(crate) redis: Arc<Stats>,
}

struct TrackedProvider {
    kind: DependencyProtocol,
    inner: Arc<dyn DependencyProvider>,
    stats: Arc<Stats>,
    probe: Arc<dyn Fn() + Send + Sync>,
}

impl DependencyProvider for TrackedProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn recognize(&self, probe: Probe<'_>) -> Recognition {
        self.inner.recognize(probe)
    }

    fn evidence(&self) -> Option<Arc<dyn traffic_protocol::evidence::EvidenceAdapter>> {
        self.inner.evidence()
    }

    fn native_protocol(&self) -> Option<Arc<dyn traffic_protocol::connection::NativeProtocol>> {
        self.inner.native_protocol()
    }

    fn create_session(&self) -> Result<Session> {
        (self.probe)();
        self.stats.sessions.fetch_add(1, Ordering::Relaxed);
        let native = self.inner.create_session()?;
        Ok(match self.kind {
            DependencyProtocol::Http => {
                Session::new::<traffic_protocol_http::HttpSession>(Box::new(TrackedHttp {
                    inner: native.bind()?,
                    stats: self.stats.clone(),
                }))
            }
            DependencyProtocol::Mysql => {
                Session::new::<traffic_protocol_mysql::MysqlSession>(Box::new(TrackedFrames {
                    inner: native.bind()?,
                    stats: self.stats.clone(),
                }))
            }
            DependencyProtocol::Redis => {
                Session::new::<traffic_protocol_redis::RedisSession>(Box::new(TrackedFrames {
                    inner: native.bind()?,
                    stats: self.stats.clone(),
                }))
            }
            _ => anyhow::bail!(
                "tracked fixture has no session adapter for {}",
                self.kind.as_str()
            ),
        })
    }
}

struct TrackedFrames<Message> {
    inner: Box<dyn FrameDecoder<Frame = Message>>,
    stats: Arc<Stats>,
}

impl<Message> FrameDecoder for TrackedFrames<Message> {
    type Frame = Message;

    fn decode(&mut self, input: &mut bytes::BytesMut) -> Result<Option<Message>> {
        let frame = self.inner.decode(input)?;
        if frame.is_some() {
            self.stats.native_calls.fetch_add(1, Ordering::Relaxed);
        }
        Ok(frame)
    }

    fn encode(&self, frame: &Message, output: &mut bytes::BytesMut) -> Result<()> {
        self.inner.encode(frame, output)
    }

    fn read_size(&self, input: &[u8]) -> Result<usize> {
        self.inner.read_size(input)
    }
}

struct TrackedHttp {
    inner: traffic_protocol_http::HttpSession,
    stats: Arc<Stats>,
}

impl traffic_protocol_http::HttpConnectionSession for TrackedHttp {
    fn configure(
        &mut self,
        builder: &mut hyper::server::conn::http1::Builder,
        preserve_header_case: bool,
    ) {
        self.stats.native_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.configure(builder, preserve_header_case);
    }
}

pub(crate) fn counted_providers() -> (Arc<DependencyProviders>, Counts) {
    counted_providers_with_probe(Arc::new(|| {}))
}

pub(crate) fn counted_providers_with_probe(
    probe: Arc<dyn Fn() + Send + Sync>,
) -> (Arc<DependencyProviders>, Counts) {
    let defaults = default_providers();
    let counts = Counts::default();
    let mut registry = DependencyProviders::default();
    for (kind, stats) in [
        (DependencyProtocol::Http, counts.http.clone()),
        (DependencyProtocol::Mysql, counts.mysql.clone()),
        (DependencyProtocol::Redis, counts.redis.clone()),
    ] {
        registry
            .register(
                kind,
                Arc::new(TrackedProvider {
                    kind,
                    inner: defaults.provider(kind).unwrap().clone(),
                    stats,
                    probe: probe.clone(),
                }),
            )
            .unwrap();
    }
    (Arc::new(registry), counts)
}

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
