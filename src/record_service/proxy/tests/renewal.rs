//! Exercise SDK reservation renewal through the real interaction relay.

use super::*;
use brz_redis::RedisServiceOptions;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Notify, oneshot};

const TTL: Duration = Duration::from_millis(180);
const TOKEN: &str = "current-owner";
const REPLACEMENT: &str = "replacement-owner";

fn runtime() -> &'static tokio::runtime::Runtime {
    // brz-net's resolver must never be tied to a discarded test runtime.
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    })
}

#[derive(Clone, Default)]
enum RenewalMode {
    #[default]
    Healthy,
    Replaced,
    BackendError,
    Blocked(Arc<ReplyGate>),
}

#[derive(Default)]
struct ReplyGate {
    entered: Notify,
    release: Notify,
}

struct RedisState {
    token: Option<String>,
    expires: Option<std::time::Instant>,
    renewals: usize,
    completions: usize,
    deletions: usize,
    mode: RenewalMode,
}

struct RedisFixture {
    state: Mutex<RedisState>,
    changed: Notify,
}

impl RedisFixture {
    fn token(&self) -> Option<String> {
        self.state.lock().unwrap().token.clone()
    }

    fn renewals(&self) -> usize {
        self.state.lock().unwrap().renewals
    }

    fn replace_on_renewal(&self, mode: RenewalMode) {
        self.state.lock().unwrap().mode = mode;
    }

    fn reset(&self, token: &str) {
        let mut state = self.state.lock().unwrap();
        state.token = Some(token.into());
        state.expires = None;
        state.mode = RenewalMode::Healthy;
    }

    async fn wait_for_renewals(&self, count: usize) {
        tokio::time::timeout(BOUND, async {
            loop {
                let changed = self.changed.notified();
                if self.renewals() >= count {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("the relay did not renew its configured short-TTL reservation");
    }

    async fn reply(&self, args: Vec<Vec<u8>>) -> String {
        assert!(args.len() >= 2);
        if args[0] == b"GET" {
            assert_eq!(args[1], b"renewal-test:inflight:all-apis");
            let mut state = self.state.lock().unwrap();
            if state
                .expires
                .is_some_and(|until| until <= std::time::Instant::now())
            {
                state.token = None;
            }
            return state.token.as_ref().map_or_else(
                || "$-1\r\n".into(),
                |token| format!("${}\r\n{token}\r\n", token.len()),
            );
        }
        assert_eq!(args[0], b"EVAL");
        assert_eq!(args[3], b"renewal-test:inflight:all-apis");
        let script = std::str::from_utf8(&args[1]).unwrap();
        if script.contains("PEXPIRE") {
            assert_eq!(args[5], TTL.as_millis().to_string().as_bytes());
            let mode = {
                let mut state = self.state.lock().unwrap();
                state.renewals += 1;
                state.mode.clone()
            };
            self.changed.notify_one();
            if let RenewalMode::Blocked(gate) = &mode {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            let mut state = self.state.lock().unwrap();
            if !matches!(mode, RenewalMode::Healthy) {
                state.token = Some(REPLACEMENT.into());
                state.expires = None;
                return if matches!(mode, RenewalMode::BackendError) {
                    "-ERR fixture renewal failure\r\n".into()
                } else {
                    ":0\r\n".into()
                };
            }
            let owned = state
                .token
                .as_ref()
                .is_some_and(|token| token.as_bytes() == args[4])
                && state
                    .expires
                    .is_none_or(|until| until > std::time::Instant::now());
            if owned {
                state.expires = Some(std::time::Instant::now() + TTL);
            }
            return if owned { ":1\r\n" } else { ":0\r\n" }.into();
        }
        assert!(script.contains("DEL"));
        let mut state = self.state.lock().unwrap();
        state.completions += 1;
        if state
            .token
            .as_ref()
            .is_some_and(|token| token.as_bytes() == args[4])
        {
            state.token = None;
            state.deletions += 1;
            ":1\r\n".into()
        } else {
            ":0\r\n".into()
        }
    }
}

async fn redis_commands(stream: TcpStream, state: Arc<RedisFixture>) {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    loop {
        let mut line = String::new();
        if read.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
        let mut args = Vec::new();
        for _ in 0..count {
            line.clear();
            read.read_line(&mut line).await.unwrap();
            let size: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
            let mut value = vec![0; size + 2];
            read.read_exact(&mut value).await.unwrap();
            value.truncate(size);
            args.push(value);
        }
        if write
            .write_all(state.reply(args).await.as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

struct RenewalFixture {
    relay: Relay<RedisService>,
    address: std::net::SocketAddr,
    redis: Arc<RedisFixture>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RenewalFixture {
    async fn new(state: crate::AppState, origin: std::net::SocketAddr) -> Self {
        let redis = Arc::new(RedisFixture {
            state: Mutex::new(RedisState {
                token: Some(TOKEN.into()),
                expires: None,
                renewals: 0,
                completions: 0,
                deletions: 0,
                mode: RenewalMode::Healthy,
            }),
            changed: Notify::new(),
        });
        let redis_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redis_address = redis_listener.local_addr().unwrap();
        let recording = redis.clone();
        let redis_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (stream, _) = redis_listener.accept().await.unwrap();
                connections.spawn(redis_commands(stream, recording.clone()));
            }
        });
        let service = RedisService::single_with_options(
            redis_address.to_string(),
            RedisServiceOptions::default().with_timeout(Duration::from_millis(300)),
        )
        .await
        .unwrap();
        let provider =
            RedisAdmissionProvider::with_ttl(service, "renewal-test", "renewal-test:url", TTL)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = Relay::new(
            Some(provider),
            format!("http://{origin}").parse().unwrap(),
            "all-apis".into(),
            BOUND,
            1024,
        )
        .with_interactions(state, format!("http://{address}").parse().unwrap());
        relay.open();
        let running = relay.clone();
        let adapter = tokio::spawn(async move {
            let (_stop, stopping) = watch::channel(false);
            serve(listener, running, stopping).await.unwrap();
        });
        Self {
            relay,
            address,
            redis,
            tasks: vec![redis_task, adapter],
        }
    }

    async fn request(&self, token: &str) -> Response<Incoming> {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        tokio::time::timeout(
            BOUND,
            client.request(
                Request::builder()
                    .uri(format!("http://{}/events", self.address))
                    .header("accept", "text/event-stream")
                    .header(ADMISSION_SCOPE_HEADER, "all-apis")
                    .header(ADMISSION_TOKEN_HEADER, token)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }

    async fn drained(&self) {
        tokio::time::timeout(BOUND, self.relay.drain())
            .await
            .unwrap();
    }
}

impl Drop for RenewalFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn first_frame(response: &mut Response<Incoming>) {
    assert_eq!(response.status(), StatusCode::OK);
    let frame = tokio::time::timeout(BOUND, response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.into_data().unwrap(), "data: first\n\n");
}

async fn stream_head(stream: &mut TcpStream, case: &CaseContext) {
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nx-traffic-e2e-case-id: {}\r\n\r\nD\r\ndata: first\n\n\r\n", case.id).as_bytes()).await.unwrap();
}

#[test]
fn sdk_renewal_spans_slow_headers_live_stream_and_eof_dependency_cleanup() {
    runtime().block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let state = state(&temp).await;
        let case = case();
        let guard = state.try_reserve_active_case(case.clone()).unwrap();
        state.activate_case_dependencies(&guard).unwrap();
        let _publication = state
            .inner
            .active_cases
            .register_interaction_publication(case.id)
            .unwrap();
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = RenewalFixture::new(state.clone(), inner.local_addr().unwrap()).await;
        let (headers, headers_ready) = oneshot::channel();
        let (finish, finishing) = oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = inner.accept().await.unwrap();
            head(&mut stream).await;
            headers_ready.await.unwrap();
            stream_head(&mut stream, &case).await;
            finishing.await.unwrap();
            stream
                .write_all(b"E\r\ndata: second\n\n\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let request = fixture.request(TOKEN);
        let release_headers = async {
            fixture.redis.wait_for_renewals(3).await;
            assert_eq!(fixture.redis.token().as_deref(), Some(TOKEN));
            headers.send(()).unwrap();
        };
        let (mut response, ()) = tokio::join!(request, release_headers);
        first_frame(&mut response).await;
        fixture
            .redis
            .wait_for_renewals(fixture.redis.renewals() + 2)
            .await;
        finish.send(()).unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "data: second\n\n"
        );
        let dependency = state.capture_dependency_targets();
        assert_eq!(dependency.cases.len(), 1);
        fixture
            .redis
            .wait_for_renewals(fixture.redis.renewals() + 2)
            .await;
        assert_eq!(fixture.relay.slot.available_permits(), 0);
        assert_eq!(fixture.redis.state.lock().unwrap().completions, 0);
        assert_eq!(fixture.redis.token().as_deref(), Some(TOKEN));
        drop(dependency);
        drop(guard);
        fixture.drained().await;
        let renewals = fixture.redis.renewals();
        tokio::time::sleep(TTL * 2 / 3).await;
        {
            let stats = fixture.redis.state.lock().unwrap();
            assert_eq!(
                stats.renewals, renewals,
                "case completion must stop renewal"
            );
            assert_eq!(stats.completions, 1);
            assert_eq!(stats.deletions, 1);
            assert!(stats.token.is_none());
        }
        assert!(fixture.relay.ready.load(Ordering::SeqCst));
        assert_eq!(state.recording_lifecycle_phase(), "running");
        upstream.await.unwrap();
    });
}

#[test]
fn renewal_loss_or_redis_error_invalidates_open_stream_or_pending_cleanup_without_deleting_replacement()
 {
    runtime().block_on(async {
        for after_eof in [false, true] {
            for mode in [RenewalMode::Replaced, RenewalMode::BackendError] {
                let temp = tempfile::tempdir().unwrap();
                let state = state(&temp).await;
                let case = case();
                let guard = state.try_reserve_active_case(case.clone()).unwrap();
                state.activate_case_dependencies(&guard).unwrap();
                let publication = state
                    .inner
                    .active_cases
                    .register_interaction_publication(case.id)
                    .unwrap();
                let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let fixture = RenewalFixture::new(state.clone(), inner.local_addr().unwrap()).await;
                let upstream = tokio::spawn(async move {
                    let (mut stream, _) = inner.accept().await.unwrap();
                    head(&mut stream).await;
                    stream_head(&mut stream, &case).await;
                    if after_eof {
                        stream.write_all(b"0\r\n\r\n").await.unwrap();
                    } else {
                        let mut remaining = Vec::new();
                        stream.read_to_end(&mut remaining).await.unwrap();
                        assert!(remaining.is_empty());
                    }
                });
                let mut response = fixture.request(TOKEN).await;
                first_frame(&mut response).await;
                let mut body = Some(response.into_body());
                if after_eof {
                    body.take().unwrap().collect().await.unwrap();
                }
                fixture.redis.replace_on_renewal(mode);
                tokio::time::timeout(BOUND, async {
                    loop {
                        // begin() owns the commit barrier. Polling it here
                        // would make a real lease loss look like a committed case.
                        if !fixture.relay.ready.load(Ordering::SeqCst)
                            && state.recording_lifecycle_phase() == "quiescing"
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("failed renewal must isolate the still-owned case");
                assert_eq!(
                    publication
                        .begin()
                        .await
                        .invalidation
                        .as_ref()
                        .unwrap()
                        .reason,
                    "interaction_reservation_lost"
                );
                if let Some(body) = body {
                    let _ = tokio::time::timeout(BOUND, body.collect())
                        .await
                        .expect("lease loss must cancel the response body");
                }
                assert!(!fixture.relay.ready.load(Ordering::SeqCst));
                assert_eq!(state.recording_lifecycle_phase(), "quiescing");
                assert_eq!(fixture.relay.slot.available_permits(), 0);
                drop(guard);
                fixture.drained().await;
                assert_eq!(fixture.redis.token().as_deref(), Some(REPLACEMENT));
                {
                    let stats = fixture.redis.state.lock().unwrap();
                    assert_eq!(stats.completions, 1);
                    assert_eq!(stats.deletions, 0);
                }
                tokio::time::timeout(BOUND, upstream)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    });
}

#[test]
fn renewal_failure_returning_after_case_completion_preserves_service_and_next_case() {
    runtime().block_on(async {
        let temp = tempfile::tempdir().unwrap();
        let state = state(&temp).await;
        let first = case();
        let second = case();
        let guard = state.try_reserve_active_case(first.clone()).unwrap();
        state.activate_case_dependencies(&guard).unwrap();
        let _publication = state
            .inner
            .active_cases
            .register_interaction_publication(first.id)
            .unwrap();
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = RenewalFixture::new(state.clone(), inner.local_addr().unwrap()).await;
        let next_case = second.clone();
        let upstream = tokio::spawn(async move {
            for case in [first, next_case] {
                let (mut stream, _) = inner.accept().await.unwrap();
                head(&mut stream).await;
                stream_head(&mut stream, &case).await;
                stream.write_all(b"0\r\n\r\n").await.unwrap();
            }
        });
        fixture
            .request(TOKEN)
            .await
            .into_body()
            .collect()
            .await
            .unwrap();
        let gate = Arc::new(ReplyGate::default());
        fixture
            .redis
            .replace_on_renewal(RenewalMode::Blocked(gate.clone()));
        tokio::time::timeout(BOUND, gate.entered.notified())
            .await
            .unwrap();
        drop(guard);
        gate.release.notify_one();
        fixture.drained().await;
        assert!(fixture.relay.ready.load(Ordering::SeqCst));
        assert_eq!(state.recording_lifecycle_phase(), "running");
        assert_eq!(fixture.redis.token().as_deref(), Some(REPLACEMENT));
        assert_eq!(fixture.redis.state.lock().unwrap().deletions, 0);

        fixture.redis.reset("next-owner");
        let guard = state.try_reserve_active_case(second.clone()).unwrap();
        state.activate_case_dependencies(&guard).unwrap();
        let _publication = state
            .inner
            .active_cases
            .register_interaction_publication(second.id)
            .unwrap();
        let response = fixture.request("next-owner").await;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await.unwrap();
        drop(guard);
        fixture.drained().await;
        assert!(fixture.relay.ready.load(Ordering::SeqCst));
        {
            let stats = fixture.redis.state.lock().unwrap();
            assert_eq!(stats.completions, 2);
            assert_eq!(stats.deletions, 1);
        }
        upstream.await.unwrap();
    });
}
