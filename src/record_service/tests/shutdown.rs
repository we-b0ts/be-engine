//! Real Source regressions for normal shutdown, publication and truncation.

use super::*;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn ordinary_case_finishes_before_source_stops_and_new_requests_are_rejected() {
    runtime().block_on(exercise("ordinary"));
}

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn sse_case_and_live_dependency_tail_finish_before_source_stops() {
    runtime().block_on(exercise("tail"));
}

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn fifteen_second_shutdown_timeout_archives_the_incomplete_case_with_shutdown_reason() {
    runtime().block_on(exercise("timeout"));
}

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn original_stream_deadline_wins_during_normal_shutdown() {
    runtime().block_on(exercise("deadline"));
}

async fn exercise(mode: &'static str) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    super::super::source::prepare_fixed_identity().unwrap();
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let work = temp.path().join("source");
    std::fs::create_dir(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let cleanup = SourceCleanup(work.join("identity"));
    let sockets = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addresses = sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect::<Vec<_>>();
    let (adapter_address, recorder_address, source_address, proxy_address) =
        (addresses[0], addresses[1], addresses[2], addresses[3]);
    let dependency = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dependency_address = dependency.local_addr().unwrap();
    let finish_dependency = Arc::new(Notify::new());
    let dependency_task = matches!(mode, "tail" | "timeout").then(|| {
        let work = work.clone();
        let finish = finish_dependency.clone();
        tokio::spawn(async move {
            let (mut stream, _) = dependency.accept().await.unwrap();
            read_request(&mut stream).await;
            std::fs::write(work.join("dependency-entered"), "ready").unwrap();
            if mode == "timeout" {
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
                return;
            }
            finish.notified().await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        })
    });
    let mut options = OptionsCli::try_parse_from([
        "record",
        "--no-interception",
        "--",
        "/usr/bin/python3",
        "-u",
        "-c",
        SOURCE,
    ])
    .unwrap()
    .options;
    options.source_command.extend([
        source_address.to_string().into(),
        proxy_address.to_string().into(),
        dependency_address.to_string().into(),
        mode.into(),
    ]);
    options.source_origin = format!("http://{source_address}");
    options.source_workdir = work.clone();
    options.listen = adapter_address;
    options.recorder_listen = recorder_address;
    options.data_root = temp.path().join("data");
    options.startup_timeout_seconds = 10;
    options.initialize_storage().unwrap();
    let mut config = options.config().unwrap();
    config.http_gateway.record_streaming = true;
    config.http_gateway.request_timeout_ms = if mode == "deadline" { 500 } else { 60_000 };
    config.http_gateway.interaction.max_duration_ms = 60_000;
    config.http_gateway.ready.path = "/ready".into();
    config.http_gateway.ready.interval_ms = 5;
    config.recording.post_ready_settle_ms = 0;
    config.recording.api_origin_dependency_idle_ms = 30;
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.case_dependency_drain_timeout_ms = 100;
    config.recording.encrypt_request_headers.clear();
    config.mysql.enabled = false;
    config.http.enabled = matches!(mode, "tail" | "timeout");
    config.http.listen = proxy_address;
    let recordings = options
        .data_root
        .join(".traffic-e2e/local/artifacts/recordings");
    drop(sockets);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let service = async {
        let mut forwards = super::super::kubernetes::PortForwards::default();
        let shutdown = async {
            stopped.await.unwrap();
            Ok(())
        };
        tokio::pin!(shutdown);
        super::super::run_prepared(options, config, &mut forwards, shutdown.as_mut()).await
    };
    let client = async {
        let mut stream = connect(adapter_address).await;
        let accept = if mode == "ordinary" {
            "application/json"
        } else {
            "text/event-stream"
        };
        stream.write_all(format!("POST /events HTTP/1.1\r\nHost: localhost\r\nAccept: {accept}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
        wait_file(&work.join("request-entered")).await;
        stop.send(()).unwrap();
        let run = std::fs::read_dir(&recordings)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let shutdown = run.join("recording-shutdown.json");
        wait_report(&shutdown, "waiting").await;
        assert!(
            !work.join("stopped").exists(),
            "Source must remain alive during case drain"
        );
        let mut late = connect(adapter_address).await;
        late.write_all(b"POST /late HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        let mut rejected = Vec::new();
        late.read_to_end(&mut rejected).await.unwrap();
        assert!(rejected.starts_with(b"HTTP/1.1 404"), "{rejected:?}");
        if matches!(mode, "ordinary" | "tail") {
            std::fs::write(work.join("release-response"), "go").unwrap();
        }
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        if mode != "timeout" {
            assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
        }
        if mode == "tail" {
            assert!(String::from_utf8_lossy(&response).contains("data: done"));
            assert!(
                !work.join("stopped").exists(),
                "primary EOF must not end a live dependency tail"
            );
            assert_eq!(read_json(&shutdown)["outcome"], "waiting");
            finish_dependency.notify_one();
            wait_file(&work.join("dependency-finished")).await;
        }
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(service, client)
    })
    .await
    .expect("shutdown must be bounded and finalize the case");
    if let Some(dependency) = dependency_task {
        dependency.await.unwrap();
    }
    let run = std::fs::read_dir(recordings)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let report = read_json(&run.join("recording-run.json"));
    let shutdown = read_json(&run.join("recording-shutdown.json"));
    assert_eq!(shutdown["case_drain_timeout_ms"], 15_000);
    assert!(
        work.join("stopped").exists(),
        "Source must be stopped before returning"
    );
    assert!(!cleanup.alive());
    if matches!(mode, "ordinary" | "tail") {
        result.unwrap();
        assert_eq!(report["published_cases"], 1);
        assert_eq!(report["failed_cases"], 0);
        assert_eq!(shutdown["outcome"], "drained");
    } else {
        assert!(result.is_err());
        assert_eq!(report["published_cases"], 0);
        assert_eq!(report["failed_cases"], 1);
        let reason = report["errors"][0]["reason"].as_str().unwrap();
        if mode == "timeout" {
            assert_eq!(reason, "shutdown_case_drain_timeout");
            assert_eq!(shutdown["outcome"], "case_drain_timeout");
            assert_eq!(shutdown["cases"][0]["failure_reason"], reason);
            assert!(shutdown["elapsed_ms"].as_u64().unwrap() >= 15_000);
        } else {
            assert_eq!(reason, "interaction_max_duration");
            assert_eq!(shutdown["outcome"], "source_stop_required");
        }
    }
    assert!(
        tokio::net::TcpStream::connect(adapter_address)
            .await
            .is_err()
    );
}

async fn connect(address: SocketAddr) -> tokio::net::TcpStream {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

async fn wait_report(path: &Path, outcome: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(contents) = std::fs::read(path)
                && let Ok(report) = serde_json::from_slice::<serde_json::Value>(&contents)
                && report["outcome"] == outcome
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

struct SourceCleanup(PathBuf);
impl SourceCleanup {
    fn alive(&self) -> bool {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|identity| identity.split_whitespace().next()?.parse::<i32>().ok())
            .is_some_and(|pid| {
                let result = unsafe { libc::kill(pid, 0) };
                result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
            })
    }
}
impl Drop for SourceCleanup {
    fn drop(&mut self) {
        if !self.alive() {
            return;
        }
        if let Some(group) = std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|identity| identity.split_whitespace().nth(1)?.parse::<i32>().ok())
        {
            let _ = std::process::Command::new("sudo")
                .args(["-n", "--", "kill", "-KILL", "--"])
                .arg(format!("-{group}"))
                .status();
        }
    }
}

const SOURCE: &str = r#"
import http.server, os, pathlib, signal, socket, sys, threading, time
source, proxy, upstream, mode = sys.argv[1:]
pathlib.Path('identity').write_text(f'{os.getpid()} {os.getpgrp()}')
def stopped(*_):
    pathlib.Path('stopped').write_text('stopped')
    sys.exit(0)
signal.signal(signal.SIGTERM, stopped)
def wait(name):
    while not pathlib.Path(name).exists(): time.sleep(0.001)
def dependency():
    host, port = proxy.split(':')
    with socket.create_connection((host, int(port))) as conn:
        conn.sendall(f'GET http://{upstream}/dependency HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n'.encode())
        while conn.recv(4096): pass
    pathlib.Path('dependency-finished').write_text('done')
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        if mode in ('tail', 'timeout'):
            threading.Thread(target=dependency, daemon=True).start()
            wait('dependency-entered')
        if mode in ('tail', 'deadline'):
            self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
            self.wfile.write(b'd\r\ndata: ready\n\n\r\n'); self.wfile.flush()
        pathlib.Path('request-entered').write_text('ready')
        wait('release-response')
        if mode == 'tail':
            self.wfile.write(b'c\r\ndata: done\n\n\r\n0\r\n\r\n'); self.wfile.flush()
        else:
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers()
            self.wfile.write(b'ok'); self.wfile.flush()
host, port = source.split(':')
http.server.ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
"#;
