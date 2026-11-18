//! Service metadata interpretation; kubectl owns Pod selection and targetPort mapping.

use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;

#[derive(Deserialize)]
struct Service {
    kind: String,
    metadata: Metadata,
    spec: Spec,
}

#[derive(Deserialize)]
struct Metadata {
    name: String,
    namespace: String,
}

#[derive(Deserialize)]
struct Spec {
    #[serde(rename = "type")]
    service_type: Option<String>,
    #[serde(default)]
    selector: std::collections::BTreeMap<String, String>,
    ports: Vec<Port>,
}

#[derive(Deserialize)]
struct Port {
    port: u16,
    protocol: Option<String>,
}

pub(super) fn tcp_ports(bytes: &[u8], namespace: &str, name: &str) -> Result<Vec<u16>> {
    // Do not include malformed response bodies: they can contain private plugin output.
    let service: Service = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("kubectl returned invalid Service JSON"))?;
    ensure!(
        service.kind == "Service"
            && service.metadata.name == name
            && service.metadata.namespace == namespace,
        "kubectl returned a different resource than Service {namespace}/{name}"
    );
    ensure!(
        service.spec.service_type.as_deref() != Some("ExternalName")
            && !service.spec.selector.is_empty(),
        "Kubernetes port-forward requires a Service selecting Pods: {namespace}/{name}"
    );
    let mut ports = std::collections::BTreeSet::new();
    for port in service.spec.ports {
        if port.protocol.as_deref().unwrap_or("TCP") != "TCP" {
            continue;
        }
        ensure!(
            port.port != 0 && ports.insert(port.port),
            "Service {namespace}/{name} has an invalid or duplicate TCP port"
        );
    }
    ensure!(
        !ports.is_empty(),
        "Service {namespace}/{name} has no TCP ports to forward"
    );
    Ok(ports.into_iter().collect())
}
