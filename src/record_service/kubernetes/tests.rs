use super::*;
use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    temp: tempfile::TempDir,
    config: AppConfig,
}

impl Fixture {
    fn new(ports: &[u16]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let program = temp.path().join("kubectl");
        std::fs::write(&program, MOCK_KUBECTL).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.dns_mock.enabled = true;
        config.tcp_gateway.enabled = true;
        config.kubernetes.kubectl_binary = program;
        config.kubernetes.kubeconfig = Some(temp.path().join("credentials"));
        config.kubernetes.context = Some("explicit-context".into());
        for host in ["api.team.svc.cluster.local", "alias.team.svc.cluster.local"] {
            config
                .upstream_routes
                .push(crate::config::UpstreamRouteConfig {
                    host: host.into(),
                    via: UpstreamTransportConfig::KubernetesPortForward {
                        namespace: "team".into(),
                        service: "api".into(),
                    },
                });
        }
        let fixture = Self { temp, config };
        fixture.settings(serde_json::json!({"ports": ports}));
        fixture
    }

    fn settings(&self, settings: serde_json::Value) {
        std::fs::write(self.temp.path().join("settings.json"), settings.to_string()).unwrap();
    }

    fn calls(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.temp.path().join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn all_service_ports_are_ready_and_aliases_share_scoped_processes() {
    let fixture = Fixture::new(&[8100, 9000]);
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    let calls = fixture.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| call["args"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg == "get"))
            .count(),
        1
    );
    assert_eq!(calls.len(), 3);
    for call in &calls {
        let args = call["args"].as_array().unwrap();
        assert!(args.iter().any(|arg| arg == "explicit-context"));
        assert!(args.iter().any(|arg| {
            arg == fixture
                .config
                .kubernetes
                .kubeconfig
                .as_ref()
                .unwrap()
                .to_str()
                .unwrap()
        }));
    }
    for port in [8100, 9000] {
        let address: SocketAddr = serde_json::from_slice(
            &std::fs::read(fixture.temp.path().join(format!("listen-{port}.json"))).unwrap(),
        )
        .unwrap();
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");
    }
    forwards.shutdown().await.unwrap();
    for port in [8100, 9000] {
        let address: SocketAddr = serde_json::from_slice(
            &std::fs::read(fixture.temp.path().join(format!("listen-{port}.json"))).unwrap(),
        )
        .unwrap();
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }
}

#[tokio::test]
async fn failed_preparation_cleans_already_ready_processes_and_never_exposes_stderr() {
    let fixture = Fixture::new(&[8100, 9000]);
    fixture.settings(serde_json::json!({"ports": [8100, 9000], "fail_port": 9000}));
    let mut forwards = PortForwards::default();
    let error = forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(!format!("{error:#}").contains("private-token"));
    let _ = forwards.shutdown().await;
    let address: SocketAddr = serde_json::from_slice(
        &std::fs::read(fixture.temp.path().join("listen-8100.json")).unwrap(),
    )
    .unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn timeout_terminates_starting_child_and_runtime_exit_is_reported() {
    let fixture = Fixture::new(&[8100]);
    fixture.settings(serde_json::json!({"ports": [8100], "stall": true}));
    let mut forwards = PortForwards::default();
    assert!(
        forwards
            .prepare(&fixture.config, Duration::from_millis(150))
            .await
            .is_err()
    );
    forwards.shutdown().await.unwrap();
    fixture.settings(serde_json::json!({"ports": [8100]}));
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    std::fs::write(fixture.temp.path().join("exit"), "").unwrap();
    let error = tokio::time::timeout(Duration::from_secs(3), forwards.failure())
        .await
        .unwrap();
    assert!(error.to_string().contains("exited"));
    forwards.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_routes_do_not_require_kubectl_or_cluster_credentials() {
    let mut config = AppConfig::default();
    config.kubernetes.kubectl_binary = PathBuf::from("/does/not/exist");
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&config, Duration::from_millis(1))
        .await
        .unwrap();
    forwards.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_kills_descendant_plugins_and_cancellation_drops_owned_forwards() {
    let fixture = Fixture::new(&[8100]);
    fixture.settings(serde_json::json!({"ports": [8100], "helper": true}));
    let mut forwards = PortForwards::default();
    forwards
        .prepare(&fixture.config, Duration::from_secs(5))
        .await
        .unwrap();
    let helper: SocketAddr =
        serde_json::from_slice(&std::fs::read(fixture.temp.path().join("helper.json")).unwrap())
            .unwrap();
    drop(tokio::net::TcpStream::connect(helper).await.unwrap());
    forwards.shutdown().await.unwrap();
    // SIGKILL delivery is asynchronous for grandchildren that cannot be reaped
    // directly by the controller. Assert bounded termination, not same-tick exit.
    tokio::time::timeout(Duration::from_secs(2), async {
        while tokio::net::TcpStream::connect(helper).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    fixture.settings(serde_json::json!({"ports": [8100]}));
    let config = fixture.config.clone();
    let (ready, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut owned = PortForwards::default();
        owned
            .prepare(&config, Duration::from_secs(5))
            .await
            .unwrap();
        ready.send(()).unwrap();
        pending::<()>().await;
    });
    receiver.await.unwrap();
    let address: SocketAddr = serde_json::from_slice(
        &std::fs::read(fixture.temp.path().join("listen-8100.json")).unwrap(),
    )
    .unwrap();
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while tokio::net::TcpStream::connect(address).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn discovery_uses_service_ports_and_rejects_unsupported_resources() {
    let service = serde_json::json!({"kind":"Service","metadata":{"name":"api","namespace":"team"},"spec":{
        "selector":{"app":"api"},"ports":[{"port":8100,"targetPort":9100,"protocol":"TCP"},{"port":53,"protocol":"UDP"},{"port":9000}]}});
    assert_eq!(
        discovery::tcp_ports(&serde_json::to_vec(&service).unwrap(), "team", "api").unwrap(),
        [8100, 9000]
    );
    for bad in [
        serde_json::json!({"selector":{},"ports":[{"port":8100}]}),
        serde_json::json!({"selector":{"app":"api"},"ports":[{"port":53,"protocol":"UDP"}]}),
        serde_json::json!({"selector":{"app":"api"},"ports":[{"port":0}]}),
        serde_json::json!({"selector":{"app":"api"},"ports":[{"port":8100},{"port":8100}]}),
    ] {
        let mut invalid = service.clone();
        invalid["spec"] = bad;
        assert!(
            discovery::tcp_ports(&serde_json::to_vec(&invalid).unwrap(), "team", "api").is_err()
        );
    }
    let mut invalid = service.clone();
    invalid["metadata"]["namespace"] = "other".into();
    assert!(discovery::tcp_ports(&serde_json::to_vec(&invalid).unwrap(), "team", "api").is_err());
}

const MOCK_KUBECTL: &str = r#"#!/usr/bin/env python3
import json, os, pathlib, socket, subprocess, sys, time
root = pathlib.Path(__file__).parent
settings = json.loads((root / 'settings.json').read_text())
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps({'args': sys.argv[1:], 'pid': os.getpid()}) + '\n')
if 'get' in sys.argv:
    print(json.dumps({'kind':'Service','metadata':{'name':'api','namespace':'team'},'spec':{'selector':{'app':'api'},'ports':[{'port':p,'targetPort':p+1,'protocol':'TCP'} for p in settings['ports']]}}))
    sys.exit(0)
port = int(sys.argv[-1][1:])
if settings.get('fail_port') == port:
    print('private-token: must not appear in public diagnostics', file=sys.stderr)
    sys.exit(3)
if settings.get('stall'):
    time.sleep(60)
if settings.get('helper'):
    helper = '''import json, signal, socket, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
s = socket.socket(); s.bind(('127.0.0.1',0)); s.listen()
open(sys.argv[1], 'w').write(json.dumps('%s:%s' % s.getsockname()))
time.sleep(60)
'''
    subprocess.Popen([sys.executable, '-c', helper, str(root / 'helper.json')])
    while not (root / 'helper.json').exists(): time.sleep(0.01)
listener = socket.socket()
listener.bind(('127.0.0.1',0))
listener.listen()
listener.settimeout(0.05)
address = listener.getsockname()
(root / ('listen-%s.json' % port)).write_text(json.dumps('%s:%s' % address))
print('Forwarding from %s:%s -> %s' % (address[0], address[1], port+1), flush=True)
while not (root / 'exit').exists():
    try:
        connection, _ = listener.accept()
        with connection:
            data = connection.recv(4096)
            connection.sendall(data)
    except socket.timeout:
        pass
sys.exit(7)
"#;
