use std::collections::{BTreeMap, BTreeSet};
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
    Breeze {
        snapshot_dir: PathBuf,
        #[serde(default)]
        capture_resources: Vec<String>,
    },
}

impl DnsMockConfig {
    pub(super) fn validate(&self) -> Result<()> {
        for strategy in &self.bypass_strategies {
            match strategy {
                DnsBypassStrategyConfig::Breeze {
                    snapshot_dir,
                    capture_resources,
                } => {
                    if snapshot_dir.as_os_str().is_empty() {
                        bail!("dns_mock Breeze bypass snapshot_dir must not be empty");
                    }
                    let mut unique = BTreeSet::new();
                    for resource in capture_resources {
                        if resource.is_empty()
                            || resource != resource.trim()
                            || resource.contains(['\r', '\n', '/', '\\'])
                        {
                            bail!(
                                "dns_mock Breeze capture resource must be one filename-safe line without surrounding whitespace"
                            );
                        }
                        if !unique.insert(resource) {
                            bail!("duplicate dns_mock Breeze capture resource {resource:?}");
                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_or_noncanonical_capture_resources() {
        let duplicate = DnsMockConfig {
            bypass_strategies: vec![DnsBypassStrategyConfig::Breeze {
                snapshot_dir: PathBuf::from("/snapshot"),
                capture_resources: vec!["usercounter".to_string(), "usercounter".to_string()],
            }],
            ..DnsMockConfig::default()
        };
        assert!(
            duplicate
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let invalid = DnsMockConfig {
            bypass_strategies: vec![DnsBypassStrategyConfig::Breeze {
                snapshot_dir: PathBuf::from("/snapshot"),
                capture_resources: vec![" usercounter ".to_string()],
            }],
            ..DnsMockConfig::default()
        };
        assert!(
            invalid
                .validate()
                .unwrap_err()
                .to_string()
                .contains("filename-safe")
        );
    }
}
