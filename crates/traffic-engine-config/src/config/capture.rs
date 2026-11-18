//! Business capture requirements compiled into Recorder transport facilities.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

pub use crate::protocol_contract::ProtocolKind as CaptureProtocol;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    pub ingress: Vec<CaptureProtocol>,
    pub dependencies: Vec<CaptureProtocol>,
}

/// Select required facilities, without discarding undeclared observed traffic.
/// This runs only at the authoring boundary; runtime overrides stay authoritative.
pub(super) fn compile(document: &mut Mapping, capture: &CaptureConfig) -> Result<()> {
    validate_protocols("ingress", &capture.ingress)?;
    validate_protocols("dependencies", &capture.dependencies)?;
    for protocol in &capture.ingress {
        let gateway = match protocol {
            CaptureProtocol::Http => "http_gateway",
            _ => anyhow::bail!(
                "recorder.capture.ingress does not support {}",
                protocol.as_str()
            ),
        };
        require(document, gateway, "enabled", "ingress", *protocol)?;
    }
    for protocol in &capture.dependencies {
        ensure!(
            crate::installed_protocols()
                .iter()
                .any(|name| *name == protocol.as_str()),
            "recorder.capture.dependencies requires an installed {} protocol implementation",
            protocol.as_str()
        );
        require(document, "dns_mock", "enabled", "dependencies", *protocol)?;
        require(
            document,
            "tcp_gateway",
            "enabled",
            "dependencies",
            *protocol,
        )?;
        require(
            document,
            "tcp_gateway.protocol_detection",
            "enabled",
            "dependencies",
            *protocol,
        )?;
        if *protocol == CaptureProtocol::Http {
            require(
                document,
                "tcp_gateway",
                "record_http",
                "dependencies",
                *protocol,
            )?;
            require(
                document,
                "tcp_gateway",
                "mitm_https",
                "dependencies",
                *protocol,
            )?;
        }
    }

    if !document.contains_key("artifacts") {
        document.insert(
            "artifacts".into(),
            serde_yaml::to_value(super::ArtifactsConfig {
                root_dir: PathBuf::from(crate::repository::LOCAL_ARTIFACTS_ROOT),
            })?,
        );
    }
    if !capture.dependencies.is_empty() {
        let artifacts_root = document
            .get("artifacts")
            .and_then(|value| value.get("root_dir"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(crate::repository::LOCAL_ARTIFACTS_ROOT));
        let dns = section(document, "dns_mock")?;
        dns.entry("registry_path".into())
            .or_insert(serde_yaml::to_value(
                artifacts_root.join("fake_dns_registry.json"),
            )?);
    }
    Ok(())
}

fn validate_protocols(role: &str, protocols: &[CaptureProtocol]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for protocol in protocols {
        ensure!(
            seen.insert(*protocol),
            "duplicate {} in recorder.capture.{role}",
            protocol.as_str()
        );
    }
    Ok(())
}

fn section<'a>(document: &'a mut Mapping, name: &str) -> Result<&'a mut Mapping> {
    let mut section = document;
    for component in name.split('.') {
        section = section
            .entry(component.into())
            .or_insert_with(|| Value::Mapping(Mapping::new()))
            .as_mapping_mut()
            .with_context(|| format!("recorder.{name} must be a mapping"))?;
    }
    Ok(section)
}

fn require(
    document: &mut Mapping,
    name: &str,
    field: &str,
    role: &str,
    protocol: CaptureProtocol,
) -> Result<()> {
    let settings = section(document, name)?;
    if let Some(explicit) = settings.get(field) {
        ensure!(
            explicit.as_bool() == Some(true),
            "recorder.capture.{role} requires {}: recorder.{name}.{field} must be true; remove the conflicting override",
            protocol.as_str()
        );
    } else {
        settings.insert(field.into(), Value::Bool(true));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
