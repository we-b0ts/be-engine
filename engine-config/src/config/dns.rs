use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{DEFAULT_DNS_MOCK_LISTEN, DEFAULT_FAKE_CIDR};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DnsMockConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub upstream_dns: SocketAddr,
    pub fake_cidr: String,
    pub ttl_seconds: u32,
    pub bypass_domains: Vec<String>,
    pub hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    pub registry_path: PathBuf,
}

impl Default for DnsMockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: DEFAULT_DNS_MOCK_LISTEN
                .parse()
                .expect("valid default DNS mock listen address"),
            upstream_dns: "10.10.10.10:53"
                .parse()
                .expect("valid default upstream DNS address"),
            fake_cidr: DEFAULT_FAKE_CIDR.to_string(),
            ttl_seconds: 60,
            bypass_domains: Vec::new(),
            hosts: BTreeMap::new(),
            registry_path: PathBuf::from("./recordings/fake_dns_registry.json"),
        }
    }
}
