use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
pub struct Stats {
    pub sessions: AtomicUsize,
    pub native_calls: AtomicUsize,
}

#[derive(Default)]
pub struct Counts {
    pub http: Arc<Stats>,
    pub mysql: Arc<Stats>,
    pub redis: Arc<Stats>,
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

pub fn counted_providers() -> (Arc<DependencyProviders>, Counts) {
    counted_providers_with_probe(Arc::new(|| {}))
}

pub fn counted_providers_with_probe(
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
