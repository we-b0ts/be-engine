use super::{OnlineRecordingOptions, proxy};
use brz_http_gateway::redis_admission::RedisAdmissionProvider;
use brz_redis::{RedisService, RedisServiceOptions};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{Notify, watch},
    task::JoinHandle,
};

mod policy;
mod project;
mod readiness;
mod sse;

#[test]
fn bounded_sse_finalizes_through_relay_and_releases_admission() {
    runtime().block_on(sse::recording_policy_through_relay(true));
}

#[test]
fn disabled_streaming_returns_404_through_relay_and_releases_admission() {
    runtime().block_on(sse::recording_policy_through_relay(false));
}

#[derive(Parser)]
struct OptionsCli {
    #[command(flatten)]
    options: OnlineRecordingOptions,
}

#[test]
fn standalone_options_keep_case_limits_without_project_or_api_filters() {
    let cli = OptionsCli::try_parse_from([
        "recording-online",
        "--advertise-url",
        "http://127.0.0.1:4080",
        "--",
        "true",
    ])
    .unwrap();
    let config = cli.options.config().unwrap();
    assert_eq!(config.http_gateway.per_api_case_limits.default, usize::MAX);
    assert!(config.http_gateway.rules.is_empty());
    assert!(config.http_gateway.exclude_rules.is_empty());
    assert!(config.http_gateway.case_path_patterns.is_empty());
    assert_eq!(
        config.recording.access_policy,
        crate::RecordingAccessPolicy::Unrestricted
    );
    let cli = OptionsCli::try_parse_from([
        "recording-online",
        "--advertise-url",
        "http://127.0.0.1:4080",
        "--case-limit",
        "5",
        "--",
        "true",
    ])
    .unwrap();
    assert_eq!(
        cli.options
            .config()
            .unwrap()
            .http_gateway
            .per_api_case_limits
            .default,
        5
    );
    assert!(
        OptionsCli::try_parse_from([
            "recording-online",
            "--advertise-url",
            "http://127.0.0.1:4080",
            "--case-limit",
            "0",
            "--",
            "true"
        ])
        .is_err()
    );
}

#[test]
fn standalone_artifact_owner_uses_numeric_ids_and_excludes_source_identity() {
    let cli = OptionsCli::try_parse_from([
        "recording-online",
        "--advertise-url",
        "http://127.0.0.1:4080",
        "--artifact-owner",
        "1115:1116",
        "--",
        "true",
    ])
    .unwrap();
    assert_eq!(
        cli.options.artifact_owner,
        Some(crate::ArtifactOwner::new(1115, 1116))
    );
    assert!(
        OptionsCli::try_parse_from([
            "recording-online",
            "--advertise-url",
            "http://127.0.0.1:4080",
            "--artifact-owner",
            "icy:icy",
            "--",
            "true",
        ])
        .is_err()
    );
    let cli = OptionsCli::try_parse_from([
        "recording-online",
        "--advertise-url",
        "http://127.0.0.1:4080",
        "--artifact-owner",
        "998:998",
        "--",
        "true",
    ])
    .unwrap();
    assert!(
        cli.options
            .storage_owner()
            .unwrap_err()
            .to_string()
            .contains("reserved Source UID")
    );
}

fn runtime() -> &'static tokio::runtime::Runtime {
    // brz-net's shared resolver outlives every test client in this binary.
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
    })
}

macro_rules! online_test {
    ($($name:ident),* $(,)?) => { $(#[test] fn $name() { runtime().block_on(cases::$name()); })* };
}
online_test!(
    all_methods_preserve_http_and_release_after_response,
    missing_stale_or_closed_admission_never_dispatches,
    busy_during_shutdown_cannot_release_active_token,
    partial_response_and_downstream_disconnect_keep_operation_alive,
    connect_failure_releases_but_dispatched_timeout_retains_slot,
    oversized_body_falls_back_before_dispatch
);

struct Fixture {
    token: Arc<Mutex<Option<String>>>,
    releases: Arc<AtomicUsize>,
    relay: proxy::Relay<RedisService>,
    url: String,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn new(origin: hyper::Uri, timeout: Duration, max_body: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = Arc::new(Mutex::new(Some("token-1".to_owned())));
        let releases = Arc::new(AtomicUsize::new(0));
        let current = token.clone();
        let completed = releases.clone();
        let redis_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let current = current.clone();
                let completed = completed.clone();
                connections.spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                        let mut args = Vec::new();
                        for _ in 0..count {
                            line.clear();
                            reader.read_line(&mut line).await.unwrap();
                            let size: usize =
                                line.trim().strip_prefix('$').unwrap().parse().unwrap();
                            let mut bytes = vec![0; size + 2];
                            reader.read_exact(&mut bytes).await.unwrap();
                            bytes.truncate(size);
                            args.push(bytes);
                        }
                        let response = {
                            let mut token = current.lock().unwrap();
                            match args[0].as_slice() {
                                b"GET" => {
                                    assert_eq!(&args[1], b"online-test:inflight:all-apis");
                                    token
                                        .as_ref()
                                        .map(|s| format!("${}\r\n{s}\r\n", s.len()))
                                        .unwrap_or_else(|| "$-1\r\n".to_owned())
                                }
                                b"EVAL" => {
                                    assert_eq!(&args[3], b"online-test:inflight:all-apis");
                                    if token.as_ref().is_some_and(|s| s.as_bytes() == args[4]) {
                                        *token = None;
                                        completed.fetch_add(1, Ordering::SeqCst);
                                        ":1\r\n".to_owned()
                                    } else {
                                        ":0\r\n".to_owned()
                                    }
                                }
                                _ => panic!("unexpected Redis command"),
                            }
                        };
                        if writer.write_all(response.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let redis = RedisService::single_with_options(
            address.to_string(),
            RedisServiceOptions::default().with_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap();
        let provider =
            RedisAdmissionProvider::new(redis, "online-test", "online-test:url").unwrap();
        let relay = proxy::Relay::new(provider, origin, "all-apis".to_owned(), timeout, max_body);
        relay.open();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = watch::channel(false);
        let running = relay.clone();
        let adapter = tokio::spawn(async move {
            let _stop = stop;
            proxy::serve(listener, running, stopped).await.unwrap();
        });
        Self {
            token,
            releases,
            relay,
            url,
            tasks: vec![redis_task, adapter],
        }
    }

    async fn request(
        &self,
        method: &str,
        token: Option<&str>,
        body: &'static str,
    ) -> (StatusCode, Bytes) {
        self.request_with_accept(method, token, body, None).await
    }

    async fn request_with_accept(
        &self,
        method: &str,
        token: Option<&str>,
        body: &'static str,
        accept: Option<&str>,
    ) -> (StatusCode, Bytes) {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let mut request = Request::builder()
            .method(method)
            .uri(format!("{}/api/example?q=x", self.url))
            .header("host", "original.example");
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        if let Some(token) = token {
            request = request
                .header("x-breeze-admission-scope", "all-apis")
                .header("x-breeze-admission-token", token);
        }
        let response = client
            .request(
                request
                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            response.into_body().collect().await.unwrap().to_bytes(),
        )
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    head.push_str(std::str::from_utf8(&body).unwrap());
    head
}

async fn wait_for_release(fixture: &Fixture) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.releases.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

mod cases {
    use super::*;

    pub async fn all_methods_preserve_http_and_release_after_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut fixture = Fixture::new(
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            Duration::from_secs(2),
            1024,
        )
        .await;
        fixture.tasks.push(tokio::spawn(async move {
            for method in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] {
                let (mut stream, _) = listener.accept().await.unwrap(); let request = read_request(&mut stream).await;
                assert!(request.starts_with(&format!("{method} /api/example?q=x HTTP/1.1")));
                assert!(request.contains("host: original.example\r\n")); assert!(request.ends_with("payload")); assert!(!request.contains("x-breeze-admission"));
                stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsource").await.unwrap();
            }
        }));
        for (index, method) in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
            .iter()
            .enumerate()
        {
            *fixture.token.lock().unwrap() = Some("token-1".to_owned());
            let (status, body) = fixture.request(method, Some("token-1"), "payload").await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(
                body.as_ref(),
                if *method == "HEAD" {
                    b"".as_slice()
                } else {
                    b"source".as_slice()
                }
            );
            assert_eq!(fixture.releases.load(Ordering::SeqCst), index + 1);
        }
    }

    pub async fn missing_stale_or_closed_admission_never_dispatches() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = Fixture::new(
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            Duration::from_secs(1),
            1024,
        )
        .await;
        assert_eq!(
            fixture.request("POST", None, "payload").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            fixture
                .request("POST", Some("stale-token"), "payload")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
        fixture.relay.close();
        assert_eq!(
            fixture.request("POST", Some("token-1"), "payload").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    pub async fn busy_during_shutdown_cannot_release_active_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = Arc::new(
            Fixture::new(
                format!("http://{}", listener.local_addr().unwrap())
                    .parse()
                    .unwrap(),
                Duration::from_secs(2),
                1024,
            )
            .await,
        );
        let started = Arc::new(Notify::new());
        let done = Arc::new(Notify::new());
        let upstream = tokio::spawn({
            let started = started.clone();
            let done = done.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                started.notify_one();
                done.notified().await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        let first = tokio::spawn({
            let fixture = fixture.clone();
            async move { fixture.request("POST", Some("token-1"), "payload").await }
        });
        started.notified().await;
        fixture.relay.close();
        assert_eq!(
            fixture.request("POST", Some("token-1"), "payload").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
        done.notify_one();
        assert_eq!(first.await.unwrap().0, StatusCode::OK);
        upstream.await.unwrap();
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 1);
    }

    pub async fn partial_response_and_downstream_disconnect_keep_operation_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = Arc::new(
            Fixture::new(
                format!("http://{}", listener.local_addr().unwrap())
                    .parse()
                    .unwrap(),
                Duration::from_secs(2),
                1024,
            )
            .await,
        );
        let started = Arc::new(Notify::new());
        let done = Arc::new(Notify::new());
        let upstream = tokio::spawn({
            let started = started.clone();
            let done = done.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_request(&mut stream).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n").await.unwrap();
                started.notify_one();
                done.notified().await;
                stream.write_all(b"0\r\n\r\n").await.unwrap();
            }
        });
        let request = tokio::spawn({
            let fixture = fixture.clone();
            async move { fixture.request("POST", Some("token-1"), "payload").await }
        });
        started.notified().await;
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
        request.abort();
        done.notify_one();
        upstream.await.unwrap();
        wait_for_release(&fixture).await;
    }

    pub async fn connect_failure_releases_but_dispatched_timeout_retains_slot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let fixture = Fixture::new(
            format!("http://{address}").parse().unwrap(),
            Duration::from_secs(1),
            1024,
        )
        .await;
        assert_eq!(
            fixture.request("POST", Some("token-1"), "payload").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 1);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = Fixture::new(
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            Duration::from_millis(100),
            1024,
        )
        .await;
        let received = Arc::new(Notify::new());
        let upstream = tokio::spawn({
            let received = received.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert!(read_request(&mut stream).await.ends_with("payload"));
                received.notify_one();
                std::future::pending::<()>().await;
            }
        });
        assert_eq!(
            fixture.request("POST", Some("token-1"), "payload").await.0,
            StatusCode::GATEWAY_TIMEOUT
        );
        received.notified().await;
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 0);
        assert!(fixture.token.lock().unwrap().is_some());
        upstream.abort();
    }

    pub async fn oversized_body_falls_back_before_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture = Fixture::new(
            format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            Duration::from_secs(1),
            3,
        )
        .await;
        assert_eq!(
            fixture.request("POST", Some("token-1"), "payload").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(fixture.releases.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
}
