//! Real Source processes prove quarantine stops and finalizes the recording service.

use super::*;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn primary_stream_timeout_stops_source_and_archives_the_original_failure() {
    runtime().block_on(exercise(false, false));
}

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn dependency_tail_deadline_stops_source_and_drains_a_dependency_that_never_replies() {
    runtime().block_on(exercise(true, false));
}

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn async_wait_outlives_primary_budget_and_explicit_shutdown_drains_original_io() {
    runtime().block_on(exercise(true, true));
}

async fn exercise(tail_timeout: bool, async_api: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    super::super::source::prepare_fixed_identity().unwrap();
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let work = temp.path().join("source");
    std::fs::create_dir(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let cleanup = SourceCleanup(work.join("identity"));
    // Reserve all addresses together so the kernel cannot return the same port twice.
    let sockets = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addresses = sockets
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect::<Vec<_>>();
    let [
        adapter_address,
        recorder_address,
        source_address,
        proxy_address,
    ] = addresses.as_slice()
    else {
        unreachable!()
    };
    let (adapter_address, recorder_address, source_address, proxy_address) = (
        *adapter_address,
        *recorder_address,
        *source_address,
        *proxy_address,
    );
    let dependency = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dependency_address = dependency.local_addr().unwrap();
    let dependency_entered = work.join("dependency-entered");
    let dependency_task = tail_timeout.then(|| {
        tokio::spawn(async move {
            let (mut stream, _) = dependency.accept().await.unwrap();
            read_request(&mut stream).await;
            std::fs::write(dependency_entered, "accepted").unwrap();
            // No response ever arrives. Source death initially produces only FIN;
            // the supervisor must close dependency transports after confirming exit.
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        })
    });
    let mut options = OptionsCli::try_parse_from([
        "traffic-e2e record",
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
        if async_api {
            "async"
        } else if tail_timeout {
            "tail"
        } else {
            "primary"
        }
        .into(),
    ]);
    options.source_origin = format!("http://{source_address}");
    options.source_workdir = work;
    options.listen = adapter_address;
    options.recorder_listen = recorder_address;
    options.data_root = temp.path().join("data");
    options.startup_timeout_seconds = 10;
    options.initialize_storage().unwrap();
    let mut config = options.config().unwrap();
    config.http_gateway.record_streaming = true;
    config.http_gateway.request_timeout_ms = 400;
    config.http_gateway.interaction.max_duration_ms = 5_000;
    config.http_gateway.ready.path = "/ready".into();
    config.http_gateway.ready.interval_ms = 5;
    config.recording.post_ready_settle_ms = 0;
    config.recording.case_dependency_post_response_window_ms = 0;
    config.recording.case_dependency_drain_timeout_ms = 100;
    config.recording.shutdown_case_drain_timeout_ms = 2_000;
    config.recording.encrypt_request_headers.clear();
    config.mysql.enabled = false;
    config.http.enabled = tail_timeout;
    config.http.listen = proxy_address;
    if async_api {
        config.async_api.insert(
            "POST /events".into(),
            serde_json::from_value(serde_json::json!({
                "when":{},"end":[{"mysql":{"sql":"UPDATE jobs SET status='completed' WHERE id=?"}}]
            }))
            .unwrap(),
        );
    }
    drop(sockets);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let service = async {
        let mut forwards = super::super::kubernetes::PortForwards::default();
        let shutdown = async {
            if async_api {
                stopped.await.unwrap();
                Ok(())
            } else {
                std::future::pending::<anyhow::Result<()>>().await
            }
        };
        tokio::pin!(shutdown);
        super::super::run_prepared(options, config, None, &mut forwards, shutdown.as_mut()).await
    };
    let client = async {
        let mut client = connect(adapter_address).await;
        let request = if async_api {
            b"POST /events HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice()
        } else {
            b"POST /events HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice()
        };
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        let result = client.read_to_end(&mut response).await;
        if let Err(error) = result {
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ));
        }
        assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
        assert!(String::from_utf8_lossy(&response).contains("data: ready\n\n"));
        if async_api {
            // The primary HTTP budget has expired, but its complete response
            // leaves the asynchronous worker and admitted dependency alive.
            tokio::time::sleep(Duration::from_millis(800)).await;
            assert!(cleanup.alive(), "waiting for an end must not stop Source");
            let mut observations = Vec::new();
            find_files(
                &temp
                    .path()
                    .join("data/.traffic-e2e/local/artifacts/recordings"),
                "async-api-observation.json",
                &mut observations,
            );
            assert!(
                observations.is_empty(),
                "neither an end nor the five-minute idle fallback has been reached"
            );
            stop.send(()).unwrap();
        }
    };
    // Explicit normal shutdown retains its existing sixty-second graceful
    // drain before interrupting this Case, whose end never arrives.
    let budget = Duration::from_secs(if async_api { 90 } else { 20 });
    let (outcome, ()) = tokio::time::timeout(budget, async {
        tokio::join!(service, client)
    })
    .await
    .expect("quarantine must stop the Source and finalize instead of keeping a fallback-only service alive");
    assert!(
        outcome.is_err(),
        "an unfinished Case cannot pass: {outcome:?}"
    );
    if let Some(dependency_task) = dependency_task {
        tokio::time::timeout(Duration::from_secs(2), dependency_task)
            .await
            .expect("confirmed Source exit must end its pending dependency transport")
            .unwrap();
    }
    assert!(
        !cleanup.alive(),
        "the fixed-identity Source must have exited before finalization returns"
    );
    assert!(
        tokio::net::TcpStream::connect(adapter_address)
            .await
            .is_err(),
        "the finalized recording must close its admission listener"
    );
    let recordings = temp
        .path()
        .join("data/.traffic-e2e/local/artifacts/recordings");
    let runs = std::fs::read_dir(recordings)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(runs.len(), 1);
    let report = read_json(&runs[0].join("recording-run.json"));
    assert_ne!(report["status"], "running");
    assert_eq!(
        report["completion_reason"],
        if async_api {
            "shutdown_signal"
        } else {
            "source_isolation_required"
        }
    );
    if async_api {
        assert_eq!(report["published_cases"], 0);
        assert_eq!(report["failed_cases"], 1);
        let shutdown = read_json(&runs[0].join("recording-shutdown.json"));
        assert_eq!(shutdown["outcome"], "case_drain_timeout");
        assert_eq!(shutdown["case_drain_timeout_ms"], 60_000);
        let mut observations = Vec::new();
        find_files(&runs[0], "async-api-observation.json", &mut observations);
        assert_eq!(observations.len(), 1);
        let observation = read_json(&observations[0]);
        assert_eq!(observation["end_reason"], "stopped");
        assert_eq!(observation["capture_complete"], true);
        assert_eq!(observation["business_complete"], false);
        assert_eq!(observation["inventory_complete"], true);
        let case = observations[0].parent().unwrap();
        assert!(case.join("expected-response.json.invalid").exists());
        assert_eq!(
            read_json(&case.join("recording-error.json"))["reason"],
            "shutdown_case_drain_timeout"
        );
        let dependencies =
            crate::recorder::test_io::read_to_string_sync(case.join("dependencies.jsonl")).unwrap();
        let terminated = dependencies
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| {
                event["event_type"] == "http_exchange"
                    && event["uri"]
                        .as_str()
                        .is_some_and(|uri| uri.ends_with("/never-replies"))
            })
            .unwrap();
        assert_eq!(observation["source_stop_required"], true);
        let reference = serde_json::json!({
            "protocol": "http", "exchange_id": terminated["id"]
        });
        assert!(
            observation["cleanup_refs"]
                .as_array()
                .unwrap()
                .contains(&reference),
            "Source stop cleanup must identify the exact original HTTP exchange"
        );
        assert!(
            terminated["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty())
        );
        assert!(terminated["response_status"].is_null());
        return;
    }
    assert_eq!(report["published_cases"], 0);
    assert_eq!(report["failed_cases"], 1);
    let mut errors = Vec::new();
    find_files(&runs[0].join("failed"), "recording-error.json", &mut errors);
    assert_eq!(errors.len(), 1);
    let failed = errors[0].parent().unwrap();
    let error = read_json(&errors[0]);
    assert_eq!(
        error["reason"],
        if tail_timeout {
            "dependency_tail_observation_timeout"
        } else {
            "interaction_max_duration"
        }
    );
    let expected = read_json(&failed.join("expected-response.json.invalid"));
    assert_eq!(
        expected["interaction"]["end"]["reason"],
        if tail_timeout {
            "server_eof"
        } else {
            "max_duration"
        }
    );
    assert_eq!(expected["interaction"]["end"]["clean"], false);
    if tail_timeout {
        let dependencies =
            crate::recorder::test_io::read_to_string_sync(failed.join("dependencies.jsonl"))
                .unwrap();
        assert!(dependencies.contains("http_exchange"));
        assert!(dependencies.contains("/never-replies"));
        let tail = read_json(&failed.join("dependency-tail-observation.json"));
        assert_eq!(tail["outcome"], "request_deadline");
    }
}

async fn connect(address: SocketAddr) -> tokio::net::TcpStream {
    loop {
        match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn find_files(directory: &Path, name: &str, output: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                find_files(&path, name, output);
            } else if path.file_name().is_some_and(|file| file == name) {
                output.push(path);
            }
        }
    }
}

struct SourceCleanup(PathBuf);

impl SourceCleanup {
    fn alive(&self) -> bool {
        crate::recorder::test_io::read_to_string_sync(&self.0)
            .ok()
            .and_then(|identity| identity.split_whitespace().next()?.parse::<i32>().ok())
            .is_some_and(|pid| {
                let result = unsafe { libc::kill(pid, 0) };
                result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            })
    }
}

impl Drop for SourceCleanup {
    fn drop(&mut self) {
        if self.alive()
            && let Ok(identity) = crate::recorder::test_io::read_to_string_sync(&self.0)
            && let Some(group) = identity
                .split_whitespace()
                .nth(1)
                .and_then(|group| group.parse::<i32>().ok())
            && group != unsafe { libc::getpgrp() }
        {
            let _ = std::process::Command::new("sudo")
                .args(["-n", "--", "kill", "-KILL", "--"])
                .arg(format!("-{group}"))
                .status();
        }
    }
}

const SOURCE: &str = r#"
import http.server, os, pathlib, socket, sys, time

source, proxy, upstream, mode = sys.argv[1:]
pathlib.Path('identity').write_text(f'{os.getpid()} {os.getpgrp()}')
dependency = None

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()
    def do_POST(self):
        global dependency
        self.rfile.read(int(self.headers['Content-Length']))
        if mode in ('tail', 'async'):
            host, port = proxy.split(':')
            dependency = socket.create_connection((host, int(port)))
            dependency.sendall(f'GET http://{upstream}/never-replies HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n'.encode())
            while not pathlib.Path('dependency-entered').exists():
                time.sleep(0.001)
        self.send_response(200)
        if mode == 'async':
            self.send_header('Content-Length', '13')
            self.end_headers()
            self.wfile.write(b'data: ready\n\n')
            self.wfile.flush()
            return
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        self.wfile.write(b'd\r\ndata: ready\n\n\r\n')
        if mode == 'tail':
            self.wfile.write(b'0\r\n\r\n')
        self.wfile.flush()
        while True:
            time.sleep(1)

host, port = source.split(':')
http.server.ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
"#;
