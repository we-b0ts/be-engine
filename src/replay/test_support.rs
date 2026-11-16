pub(crate) mod recording;
use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use crate::recording_network::{
    RECORDING_NETWORK_FILENAME, RecordedEndpoint, RecordingNetworkManifest,
};

pub(crate) fn write_test_recording_network_manifest(root_dir: &Path) {
    // Protocol tests author semantic JSONL fixtures directly. Pair those fixtures with the
    // run-level network artifact that the real Recorder now writes.
    if let Some(run) = crate::dependency_index::recording::root(root_dir) {
        assert!(
            run.join(RECORDING_NETWORK_FILENAME).is_file(),
            "central fixture needs its sealed run network contract"
        );
        return;
    }
    let manifest_path = root_dir.join(RECORDING_NETWORK_FILENAME);
    if manifest_path.is_file() {
        return;
    }
    let mut endpoints = BTreeSet::new();
    collect_recording_endpoints(root_dir, &mut endpoints);
    let (global, debug) = super::find_run_level_dependencies(root_dir);
    for path in global.into_iter().chain(debug) {
        collect_recording_endpoints(&path, &mut endpoints);
    }
    let resolved_domains = endpoints
        .iter()
        .map(|endpoint: &RecordedEndpoint| endpoint.host.clone())
        .collect();
    let manifest = RecordingNetworkManifest::from_observations(resolved_domains, endpoints);
    std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

fn collect_recording_endpoints(root: &Path, endpoints: &mut BTreeSet<RecordedEndpoint>) {
    if root.is_dir() {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().and_then(|name| name.to_str()) == Some(".replay") {
                continue;
            }
            collect_recording_endpoints(&path, endpoints);
        }
        return;
    }
    if root.extension().and_then(|extension| extension.to_str()) != Some("jsonl") {
        return;
    }
    for line in std::fs::read_to_string(root).unwrap().lines() {
        if line.trim().is_empty() {
            continue;
        }
        collect_json_endpoints(&serde_json::from_str(line).unwrap(), endpoints);
    }
}

fn collect_json_endpoints(value: &Value, endpoints: &mut BTreeSet<RecordedEndpoint>) {
    let Some(object) = value.as_object() else {
        if let Some(values) = value.as_array() {
            for value in values {
                collect_json_endpoints(value, endpoints);
            }
        }
        return;
    };
    if let (Some(host), Some(port)) = (
        object.get("target_host").and_then(Value::as_str),
        object
            .get("target_port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok()),
    ) {
        endpoints.insert(RecordedEndpoint::new(host, port).unwrap());
    }
    if let (Some(host), Some(port)) = (
        object.get("host").and_then(Value::as_str),
        object
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok()),
    ) {
        endpoints.insert(RecordedEndpoint::new(host, port).unwrap());
    }
    if object.get("event_type").and_then(Value::as_str) == Some("http_exchange")
        && let (Some(scheme), Some(authority)) = (
            object.get("scheme").and_then(Value::as_str),
            object.get("authority").and_then(Value::as_str),
        )
    {
        let authority = authority.parse::<hyper::http::uri::Authority>().unwrap();
        let port = authority
            .port_u16()
            .unwrap_or(if matches!(scheme, "https" | "fake_ip_https") {
                443
            } else {
                80
            });
        endpoints.insert(RecordedEndpoint::new(authority.host(), port).unwrap());
    }
    if object.get("event_type").and_then(Value::as_str) == Some("tcp_gateway_connection")
        && let (Some(domain), Some(fake_addr)) = (
            object.get("domain").and_then(Value::as_str),
            object.get("fake_addr").and_then(Value::as_str),
        )
    {
        let port = fake_addr.parse::<std::net::SocketAddr>().unwrap().port();
        endpoints.insert(RecordedEndpoint::new(domain, port).unwrap());
    }
    for value in object.values() {
        collect_json_endpoints(value, endpoints);
    }
}

/// Exercise the same shared serving port used by registered protocol providers.
pub(crate) async fn serve_native(
    stream: tokio::net::TcpStream,
    target: super::ReplayTarget,
    state: std::sync::Arc<tokio::sync::Mutex<crate::protocols::replay::ReplayState>>,
) -> anyhow::Result<()> {
    let peer = stream.peer_addr()?;
    super::native::handle_connection(stream, peer, target, state).await
}
