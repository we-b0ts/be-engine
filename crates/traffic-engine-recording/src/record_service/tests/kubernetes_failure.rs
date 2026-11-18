//! A forwarding exit stops the real Source and fails its recording immediately.

use super::*;
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn healthy_port_forward_survives_until_normal_recording_shutdown() {
    runtime().block_on(exercise(false));
}

#[test]
#[ignore = "requires python3 and root or passwordless sudo for the fixed Source UID; no interception"]
fn first_port_forward_exit_fails_the_whole_batch_without_restarting() {
    runtime().block_on(exercise(true));
}

async fn exercise(unexpected_exit: bool) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    super::super::source::prepare_fixed_identity().unwrap();
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let work = temp.path().join("source");
    std::fs::create_dir(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let cleanup = SourceCleanup(work.join("identity"));
    let mock = temp.path().join("kubectl");
    std::fs::write(&mock, KUBECTL).unwrap();
    std::fs::set_permissions(&mock, std::fs::Permissions::from_mode(0o755)).unwrap();
    let sockets = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addresses = sockets
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect::<Vec<_>>();
    let (adapter, recorder, source) = (addresses[0], addresses[1], addresses[2]);
    let dns = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
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
    options.source_command.push(source.to_string().into());
    options.source_origin = format!("http://{source}");
    options.source_workdir = work.clone();
    options.listen = adapter;
    options.recorder_listen = recorder;
    options.data_root = temp.path().join("data");
    options.run_id = Some("20261025000001".into());
    options.startup_timeout_seconds = 10;
    options.initialize_storage().unwrap();
    let mut config = options.config().unwrap();
    config.mysql.enabled = false;
    config.udp_gateway.enabled = false;
    // Declared Kubernetes routes require both listeners even though this
    // synthetic Source uses its fixed loopback address without interception.
    config.dns_mock.enabled = true;
    config.tcp_gateway.enabled = true;
    config.dns_mock.listen = dns.local_addr().unwrap();
    config.tcp_gateway.listen = addresses[3];
    config.http_gateway.ready.path = "/ready".into();
    config.http_gateway.ready.interval_ms = 5;
    config.recording.post_ready_settle_ms = 0;
    config.recording.encrypt_request_headers.clear();
    config.recording.case_dependency_post_response_window_ms = 0;
    config.kubernetes.kubectl_binary = mock;
    config
        .upstream_routes
        .push(crate::config::UpstreamRouteConfig {
            host: "api.team.svc.cluster.local".into(),
            via: crate::config::UpstreamTransportConfig::KubernetesPortForward {
                namespace: "team".into(),
                service: "api".into(),
            },
        });
    let recordings = options
        .data_root
        .join(".traffic-e2e/local/artifacts/recordings");
    let run = recordings.join("20261025000001");
    drop(sockets);
    drop(dns);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut stop = Some(stop);
    let service = async {
        let mut forwards = super::super::kubernetes::PortForwards::default();
        forwards
            .prepare(&config, Duration::from_secs(5))
            .await
            .unwrap();
        wait_file(&temp.path().join("ready-1")).await;
        let port =
            crate::recorder::test_io::read_to_string_sync(temp.path().join("ready-1")).unwrap();
        options
            .source_command
            .push(format!("127.0.0.1:{port}").into());
        let shutdown = async {
            stopped.await.unwrap();
            Ok(())
        };
        tokio::pin!(shutdown);
        let result =
            super::super::run_prepared(options, config, None, &mut forwards, shutdown.as_mut())
                .await;
        if let Err(error) = &result {
            eprintln!("synthetic Source recording failed: {error:#}");
        }
        result
    };
    let client = async {
        request(adapter, "/before").await;
        wait_count(&run, 1).await;
        let pid = crate::recorder::test_io::read_to_string_sync(work.join("identity")).unwrap();
        if unexpected_exit {
            std::fs::write(temp.path().join("exit-1"), "go").unwrap();
            return;
        }
        request(adapter, "/after").await;
        wait_count(&run, 2).await;
        assert_eq!(
            crate::recorder::test_io::read_to_string_sync(work.join("identity")).unwrap(),
            pid
        );
        assert_eq!(std::fs::read_dir(&recordings).unwrap().count(), 1);
        stop.take().unwrap().send(()).unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(service, client)
    })
    .await
    .expect("forward exit must stop Source and finalize the failed batch");
    let manifest = read_json(&run.join("recording-run.json"));
    if unexpected_exit {
        let error = format!("{:#}", result.unwrap_err());
        assert!(
            error.contains("exited (exit status: 0)") && error.contains("connection_lost"),
            "{error}"
        );
        assert_eq!(manifest["status"], "failed");
        assert_eq!(manifest["published_cases"], 1);
    } else {
        result.unwrap();
        assert_eq!(manifest["status"], "completed");
        assert_eq!(manifest["completion_reason"], "shutdown_signal");
        assert_eq!(manifest["published_cases"], 2);
    }
    assert_eq!(manifest["failed_cases"], 0);
    assert_eq!(std::fs::read_dir(&recordings).unwrap().count(), 1);
    assert_eq!(
        crate::recorder::test_io::read_to_string_sync(temp.path().join("forwards")).unwrap(),
        "1"
    );
    assert!(!cleanup.alive());
}

async fn request(address: SocketAddr, path: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let Ok(mut socket) = tokio::net::TcpStream::connect(address).await else {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            };
            socket
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            socket.read_to_end(&mut response).await.unwrap();
            // Manifest publication precedes admission release. Only poll an
            // explicit busy rejection, which has never been sent to Source.
            if response.starts_with(b"HTTP/1.1 404") && response.ends_with(b"recorder busy") {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
            assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
            assert!(
                response.ends_with(b"upstream-ok"),
                "Source must receive the real third-party response: {response:?}"
            );
            return;
        }
    })
    .await
    .unwrap();
}

async fn wait_count(root: &Path, count: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = std::fs::read(root.join("recording-run.json"))
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && value["published_cases"] == count
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
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
        crate::recorder::test_io::read_to_string_sync(&self.0).ok().and_then(|s| s.trim().parse::<i32>().ok())
            .is_some_and(|pid| unsafe { libc::kill(pid, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
    }
}
impl Drop for SourceCleanup {
    fn drop(&mut self) {
        if self.alive()
            && let Ok(pid) = crate::recorder::test_io::read_to_string_sync(&self.0)
        {
            let _ = std::process::Command::new("sudo")
                .args(["-n", "--", "kill", "-KILL"])
                .arg(pid.trim())
                .status();
        }
    }
}

const SOURCE: &str = r#"
import http.server, os, pathlib, sys, urllib.request
pathlib.Path('identity').write_text(str(os.getpid()))
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        if self.path == '/ready':
            body = b'ready'
        else:
            direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with direct.open('http://' + sys.argv[2] + '/third-party', timeout=2) as reply:
                body = reply.read()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
host, port = sys.argv[1].split(':')
http.server.ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
"#;

const KUBECTL: &str = r#"#!/usr/bin/env python3
import json, pathlib, socket, sys, time
root = pathlib.Path(__file__).parent
if 'get' in sys.argv:
    print(json.dumps({'kind':'Service','metadata':{'name':'api','namespace':'team'},'spec':{'selector':{'app':'api'},'ports':[{'port':8100,'targetPort':8100,'protocol':'TCP'}]}})); sys.exit(0)
counter = root / 'forwards'
generation = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(generation))
local, remote = sys.argv[-1].split(':')
listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('127.0.0.1', int(local or '0'))); listener.listen()
listener.settimeout(0.02)
print('Forwarding from 127.0.0.1:%s -> 8100' % listener.getsockname()[1], flush=True)
(root / ('ready-%s' % generation)).write_text(str(listener.getsockname()[1]))
while not (root / ('exit-%s' % generation)).exists():
    try:
        connection, _ = listener.accept()
        with connection:
            request = b''
            while b'\r\n\r\n' not in request: request += connection.recv(4096)
            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok')
    except socket.timeout:
        pass
print('lost connection to pod private-token', file=sys.stderr, flush=True); sys.exit(0)
"#;
