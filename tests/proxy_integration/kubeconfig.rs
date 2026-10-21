//! Own kubeconfig rewrite fixture ports through startup and join every server.
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use traffic_e2e::{
    AppConfig, AppState, FakeDnsUpstreamProtocol, HttpGatewayRuleConfig, HttpResponseRewriteConfig,
    HttpResponseRewritePluginConfig, HttpResponseRewriteRuleConfig,
};

use super::{only_recording_run_dir, raw_http_get_with_host, wait_for_http_cases, wait_for_port};

const CLUSTER: &str = "c142fe56e07d04a749c1630fb5f1b680b";
const ORIGINAL_IP: &str = "182.92.232.38";

pub(super) enum ProxyAddress {
    Reserved,
    GatewayCollision,
}

pub(super) async fn verify(mode: ProxyAddress) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let temp = tempdir().unwrap();
    let mut tasks = JoinSet::<Result<()>>::new();
    let original = format!(
        "apiVersion: v1\nclusters:\n- cluster:\n    server: https://{ORIGINAL_IP}:6443\n    certificate-authority-data: REDACTED\n  name: kubernetes\nusers:\n- name: admin\n  user:\n    client-key-data: REDACTED\n"
    );
    let body =
        serde_json::json!({"config":original,"expiration":"2027-01-01T00:00:00Z"}).to_string();
    let matched = upstream(&mut tasks, "application/json;charset=utf-8", body).await;
    let fallback = upstream(&mut tasks, "text/plain", "fallback".into()).await;

    // Keep all addresses owned while configuration and certificates initialize.
    // A released bind(:0) can immediately be returned by the next bind(:0).
    let gateway = reserved_socket();
    let gateway_addr = gateway.local_addr().unwrap();
    let tcp_gateway = reserved_socket();
    let tcp_gateway_addr = tcp_gateway.local_addr().unwrap();
    let proxy = reserved_socket();
    let collision = matches!(mode, ProxyAddress::GatewayCollision);
    let proxy_addr = if collision {
        gateway_addr
    } else {
        proxy.local_addr().unwrap()
    };
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    let started = temp.path().join("proxy-started");
    let captured = temp.path().join("captured-kubeconfig");
    let proxy_input = temp.path().join("proxy-kubeconfig-path");
    let binary = temp.path().join("fake-kubectl");
    std::fs::write(&binary, format!(
        "#!/bin/sh\nset -eu\nkubeconfig=\"\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--kubeconfig\" ]; then\n    shift\n    kubeconfig=\"$1\"\n  fi\n  shift\ndone\ncp \"$kubeconfig\" '{}'\nprintf '%s' \"$kubeconfig\" > '{}'\ntouch '{}'\nexec sleep 30\n", captured.display(), proxy_input.display(), started.display()
    )).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    if !collision {
        let started = started.clone();
        tasks.spawn(async move {
            while !started.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Bound but not listening until the child starts: the manager's
            // unmanaged-listener check must still observe connection refused.
            let listener = proxy
                .listen(128)
                .context("fake kubectl listener startup failed")?;
            loop {
                let _ = listener.accept().await?;
            }
        });
    } else {
        drop(proxy);
    }

    let mut config = AppConfig::default();
    config.dns_mock.enabled = true;
    config.dns_mock.listen = dns.local_addr().unwrap();
    config.dns_mock.registry_path = temp.path().join("dns-registry.json");
    config.tcp_gateway.enabled = true;
    config.tcp_gateway.listen = tcp_gateway_addr;
    config.http_gateway.enabled = true;
    config.http_gateway.listen = gateway_addr;
    config.http_gateway.matched_upstream = format!("http://{matched}");
    config.http_gateway.fallback_upstream = format!("http://{fallback}");
    config.http_gateway.rules = vec![HttpGatewayRuleConfig {
        name: Some("api".into()),
        methods: vec!["GET".into()],
        path_prefixes: vec!["/api/".into()],
        ..Default::default()
    }];
    config.http_response_rewrite = HttpResponseRewriteConfig {
        enabled: true,
        rules: vec![HttpResponseRewriteRuleConfig {
            source_evidence: String::new(),
            name: "pluto-kubeconfig".into(),
            authorities: vec!["cs.aliyuncs.com".into()],
            methods: vec!["GET".into()],
            path: format!("/api/v2/k8s/{CLUSTER}/user_config"),
            path_pattern: None,
            pointers: Vec::new(),
            status_codes: vec![200],
            content_types: vec!["application/json".into()],
            plugin: Some(HttpResponseRewritePluginConfig::PlutoEciKubeconfig {
                kubectl_binary: binary.to_string_lossy().into_owned(),
                proxy_listen: proxy_addr,
            }),
        }],
    };
    config.mysql.enabled = false;
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    let state = AppState::new(config).await.unwrap();
    let (stop, stopped) = oneshot::channel();
    let app_state = state.clone();
    let app_id = tasks
        .spawn(async move {
            // Hand ordinary ports to the runtime only when it is ready to bind.
            drop((gateway, tcp_gateway, dns));
            app_state
                .run_until(None, async move {
                    stopped.await.context("test shutdown sender dropped")?;
                    Ok(())
                })
                .await
        })
        .id();
    tokio::select! {
        _ = async { wait_for_port(gateway_addr).await; wait_for_port(tcp_gateway_addr).await; } => {},
        result = tasks.join_next() => panic!("kubeconfig fixture stopped during startup: {result:?}"),
    }

    let response = raw_http_get_with_host(
        gateway_addr,
        &format!("/api/v2/k8s/{CLUSTER}/user_config"),
        "cs.aliyuncs.com",
    )
    .await;
    let alias = format!("k8s-{CLUSTER}.pluto-eci.trp.test");
    if collision {
        assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
        assert!(response.contains(&format!("kubectl proxy listen address {proxy_addr} is already in use by an unmanaged process")), "{response}");
        assert!(
            !started.exists() && !captured.exists(),
            "occupied port must reject before spawning kubectl"
        );
        assert!(
            state
                .dns_registry()
                .get_response_alias_by_domain(&alias)
                .await
                .is_none()
        );
    } else {
        assert!(
            response.starts_with("HTTP/1.1 200 "),
            "kubeconfig rewrite failed; gateway={gateway_addr}, proxy={proxy_addr}, tcp_gateway={tcp_gateway_addr}, response={response:?}"
        );
        assert!(!response.to_ascii_lowercase().contains("etag:"));
        let payload: Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_kubeconfig(
            &payload,
            &alias,
            proxy_addr,
            state.ca().ca_cert_pem().as_bytes(),
        );
        assert_eq!(std::fs::read_to_string(&captured).unwrap(), original);
        let entry = state
            .dns_registry()
            .get_response_alias_by_domain(&alias)
            .await
            .unwrap();
        assert_eq!(entry.real_ips, vec![Ipv4Addr::LOCALHOST]);
        assert_eq!(
            entry.upstream_authority.as_deref(),
            Some(proxy_addr.to_string().as_str())
        );
        assert_eq!(entry.upstream_protocol, Some(FakeDnsUpstreamProtocol::Http));
        wait_for_http_cases(
            &temp.path().join("recordings"),
            &[(format!("apis/api-v2-k8s-{CLUSTER}-user_config").as_str(), 1)],
            1,
            0,
        )
        .await;
    }

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (id, result) = tasks
                .join_next_with_id()
                .await
                .expect("recorder completion missing")
                .unwrap();
            result.unwrap();
            if id == app_id {
                break;
            }
        }
    })
    .await
    .expect("recorder did not shut down");
    tasks.shutdown().await;
    assert!(
        TcpStream::connect(proxy_addr).await.is_err(),
        "proxy listener leaked after shutdown"
    );
    if !collision {
        let input_path = std::fs::read_to_string(proxy_input).unwrap();
        assert!(
            !Path::new(&input_path).exists(),
            "private proxy kubeconfig leaked after shutdown"
        );
        assert_recorded_kubeconfig(
            temp.path(),
            &alias,
            proxy_addr,
            state.ca().ca_cert_pem().as_bytes(),
        );
    }
}

fn reserved_socket() -> TcpSocket {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket
}

async fn upstream(
    tasks: &mut JoinSet<Result<()>>,
    content_type: &'static str,
    body: String,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tasks.spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            anyhow::ensure!(headers.len() < 16_384 && stream.read(&mut byte).await? == 1, "incomplete fixture HTTP request");
            headers.push(byte[0]);
        }
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nETag: original\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
        Ok(())
    });
    addr
}

fn assert_kubeconfig(payload: &Value, alias: &str, proxy: SocketAddr, ca: &[u8]) {
    let text = payload["config"].as_str().unwrap();
    let config: serde_yaml::Value = serde_yaml::from_str(text).unwrap();
    assert_eq!(
        config["clusters"][0]["cluster"]["server"].as_str(),
        Some(format!("https://{alias}:{}", proxy.port()).as_str())
    );
    assert_eq!(
        STANDARD
            .decode(
                config["clusters"][0]["cluster"]["certificate-authority-data"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
        ca
    );
    assert!(text.contains("client-key-data: REDACTED"));
    assert!(!text.contains(ORIGINAL_IP));
}

fn assert_recorded_kubeconfig(root: &Path, alias: &str, proxy: SocketAddr, ca: &[u8]) {
    let run = only_recording_run_dir(&root.join("recordings"));
    let group = run.join(format!("apis/api-v2-k8s-{CLUSTER}-user_config"));
    let case = std::fs::read_dir(group)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(case.join("expected-response.json")).unwrap())
            .unwrap();
    let body: Value = serde_json::from_str(expected["body"]["data"].as_str().unwrap()).unwrap();
    assert_kubeconfig(&body, alias, proxy, ca);
}
