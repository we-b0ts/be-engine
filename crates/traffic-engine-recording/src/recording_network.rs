use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

pub const RECORDING_NETWORK_FILENAME: &str = "recording-network.json";
const RECORDING_NETWORK_VERSION: u8 = 1;
const MAX_RECORDED_DOMAINS: usize = 100_000;
const MAX_RECORDED_ENDPOINTS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordedEndpoint {
    pub host: String,
    pub port: u16,
}

impl RecordedEndpoint {
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn new(host: &str, port: u16) -> Result<Self> {
        ensure!(port != 0, "recorded endpoint port must not be zero");
        Ok(Self {
            host: normalize_host(host)?,
            port,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingNetworkManifest {
    version: u8,
    pub resolved_domains: Vec<String>,
    pub accessed_endpoints: Vec<RecordedEndpoint>,
}

impl RecordingNetworkManifest {
    pub fn from_observations(
        resolved_domains: BTreeSet<String>,
        accessed_endpoints: BTreeSet<RecordedEndpoint>,
    ) -> Self {
        Self {
            version: RECORDING_NETWORK_VERSION,
            resolved_domains: resolved_domains.into_iter().collect(),
            accessed_endpoints: accessed_endpoints.into_iter().collect(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let source = std::fs::read(path).with_context(|| {
            format!(
                "failed to read recording network manifest {}",
                path.display()
            )
        })?;
        let manifest: Self = serde_json::from_slice(&source).with_context(|| {
            format!(
                "failed to parse recording network manifest {}",
                path.display()
            )
        })?;
        manifest.validate(path)?;
        Ok(manifest)
    }

    fn validate(&self, path: &Path) -> Result<()> {
        ensure!(
            self.version == RECORDING_NETWORK_VERSION,
            "unsupported recording network manifest version {} in {}",
            self.version,
            path.display()
        );
        ensure!(
            self.resolved_domains.len() <= MAX_RECORDED_DOMAINS,
            "recording network manifest {} exceeds the resolved-domain limit",
            path.display()
        );
        ensure!(
            self.accessed_endpoints.len() <= MAX_RECORDED_ENDPOINTS,
            "recording network manifest {} exceeds the endpoint limit",
            path.display()
        );
        let mut domains = BTreeSet::new();
        for domain in &self.resolved_domains {
            ensure!(
                normalize_host(domain)? == *domain && domains.insert(domain),
                "recording network manifest {} has a duplicate or noncanonical domain {:?}",
                path.display(),
                domain
            );
        }
        let mut endpoints = BTreeSet::new();
        for endpoint in &self.accessed_endpoints {
            ensure!(
                RecordedEndpoint::new(&endpoint.host, endpoint.port)? == *endpoint
                    && endpoints.insert(endpoint),
                "recording network manifest {} has a duplicate or noncanonical endpoint {}:{}",
                path.display(),
                endpoint.host,
                endpoint.port
            );
        }
        Ok(())
    }
}

pub fn normalize_host(host: &str) -> Result<String> {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    ensure!(
        !normalized.is_empty()
            && normalized == normalized.trim()
            && !normalized.contains(['\r', '\n', '/', '\\']),
        "recorded network host must be one non-empty canonical host name or IP address"
    );
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_canonical_unique_network_observations() {
        let endpoint = RecordedEndpoint::new("CACHE.EXAMPLE.COM.", 6379).unwrap();
        assert_eq!(endpoint.host, "cache.example.com");

        let manifest = RecordingNetworkManifest::from_observations(
            BTreeSet::from(["cache.example.com".to_string()]),
            BTreeSet::from([endpoint]),
        );
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), serde_json::to_vec(&manifest).unwrap()).unwrap();
        let loaded = RecordingNetworkManifest::load(temp.path()).unwrap();
        assert_eq!(loaded.accessed_endpoints.len(), 1);
    }
}
