use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::DEFAULT_FAKE_CIDR;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsMockConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub upstream_dns: SocketAddr,
    pub fake_cidr: String,
    pub ttl_seconds: u32,
    pub bypass_domains: Vec<String>,
    pub bypass_strategies: Vec<DnsBypassStrategyConfig>,
    pub hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    pub registry_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
pub enum DnsBypassStrategyConfig {
    Breeze { snapshot_dir: PathBuf },
}

impl DnsMockConfig {
    pub(super) fn validate(&self) -> Result<()> {
        for strategy in &self.bypass_strategies {
            match strategy {
                DnsBypassStrategyConfig::Breeze { snapshot_dir } => {
                    if snapshot_dir.as_os_str().is_empty() {
                        bail!("dns_mock Breeze bypass snapshot_dir must not be empty");
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for DnsMockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.153:15353"
                .parse()
                .expect("valid default DNS mock listen address"),
            upstream_dns: "10.10.10.10:53"
                .parse()
                .expect("valid default upstream DNS address"),
            fake_cidr: DEFAULT_FAKE_CIDR.to_string(),
            ttl_seconds: 60,
            bypass_domains: Vec::new(),
            bypass_strategies: Vec::new(),
            hosts: BTreeMap::new(),
            registry_path: PathBuf::from("./recordings/fake_dns_registry.json"),
        }
    }
}
