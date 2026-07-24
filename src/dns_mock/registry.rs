use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::Duration;

use super::bypass::normalize_domain;

pub(crate) const FLUSH_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FakeDnsUpstreamProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FakeDnsEntry {
    pub domain: String,
    pub fake_ip: Ipv4Addr,
    pub real_ips: Vec<Ipv4Addr>,
    #[serde(default)]
    pub response_alias: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_protocol: Option<FakeDnsUpstreamProtocol>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Clone)]
pub struct FakeDnsRegistry {
    inner: Arc<Mutex<RegistryInner>>,
    flush_lock: Arc<Mutex<()>>,
}

struct RegistryInner {
    cidr: Ipv4Cidr,
    next_offset: u32,
    by_domain: HashMap<String, FakeDnsEntry>,
    by_fake_ip: HashMap<Ipv4Addr, String>,
    registry_path: Option<PathBuf>,
    revision: u64,
    persisted_revision: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct PersistedRegistry {
    entries: Vec<FakeDnsEntry>,
}

struct RegistrySnapshot {
    path: PathBuf,
    entries: Vec<FakeDnsEntry>,
    revision: u64,
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    size: u32,
}

impl FakeDnsRegistry {
    pub fn new(fake_cidr: &str) -> Result<Self> {
        Self::load_or_new(fake_cidr, None::<&Path>, &[])
    }

    pub fn load_or_new(
        fake_cidr: &str,
        registry_path: Option<impl AsRef<Path>>,
        _bypass_domains: &[String],
    ) -> Result<Self> {
        let cidr = Ipv4Cidr::parse(fake_cidr)?;
        let registry_path = registry_path.map(|path| path.as_ref().to_path_buf());
        let mut inner = RegistryInner {
            cidr,
            next_offset: 1,
            by_domain: HashMap::new(),
            by_fake_ip: HashMap::new(),
            registry_path,
            revision: 0,
            persisted_revision: 0,
        };
        inner.load_persisted_entries()?;

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            flush_lock: Arc::new(Mutex::new(())),
        })
    }

    pub async fn get_by_fake_ip(&self, fake_ip: Ipv4Addr) -> Option<FakeDnsEntry> {
        let inner = self.inner.lock().await;
        let domain = inner.by_fake_ip.get(&fake_ip)?;
        inner.by_domain.get(domain).cloned()
    }

    pub async fn get_response_alias_by_domain(&self, domain: &str) -> Option<FakeDnsEntry> {
        let inner = self.inner.lock().await;
        inner
            .by_domain
            .get(&normalize_domain(domain))
            .filter(|entry| entry.response_alias)
            .cloned()
    }

    pub async fn register_response_alias(
        &self,
        domain: &str,
        real_ip: Ipv4Addr,
        upstream_authority: &str,
        upstream_protocol: FakeDnsUpstreamProtocol,
    ) -> Result<FakeDnsEntry> {
        self.allocate_or_update_entry(
            domain,
            vec![real_ip],
            true,
            Some(upstream_authority.to_string()),
            Some(upstream_protocol),
        )
        .await
    }

    pub async fn register_raw_tcp_response_alias(
        &self,
        alias: &str,
        real_ip: Ipv4Addr,
    ) -> Result<FakeDnsEntry> {
        self.allocate_or_update_entry(alias, vec![real_ip], true, None, None)
            .await
    }

    pub(crate) async fn flush_if_dirty(&self) -> Result<bool> {
        let _flush_guard = self.flush_lock.lock().await;
        let snapshot = {
            let inner = self.inner.lock().await;
            inner.persistence_snapshot()
        };
        let Some(snapshot) = snapshot else {
            return Ok(false);
        };
        let revision = snapshot.revision;

        task::spawn_blocking(move || persist_snapshot(snapshot))
            .await
            .context("fake DNS registry persistence task failed")??;

        let mut inner = self.inner.lock().await;
        inner.persisted_revision = inner.persisted_revision.max(revision);
        Ok(true)
    }

    pub(super) async fn allocate_or_update(
        &self,
        domain: &str,
        real_ips: Vec<Ipv4Addr>,
    ) -> Result<FakeDnsEntry> {
        self.allocate_or_update_entry(domain, real_ips, false, None, None)
            .await
    }

    async fn allocate_or_update_entry(
        &self,
        domain: &str,
        real_ips: Vec<Ipv4Addr>,
        response_alias: bool,
        upstream_authority: Option<String>,
        upstream_protocol: Option<FakeDnsUpstreamProtocol>,
    ) -> Result<FakeDnsEntry> {
        let mut inner = self.inner.lock().await;
        let key = normalize_domain(domain);
        if let Some(entry) = inner.by_domain.get_mut(&key) {
            let changed = entry.real_ips != real_ips
                || entry.response_alias != response_alias
                || entry.upstream_authority != upstream_authority
                || entry.upstream_protocol != upstream_protocol;
            if changed {
                entry.real_ips = real_ips;
                entry.response_alias = response_alias;
                entry.upstream_authority = upstream_authority;
                entry.upstream_protocol = upstream_protocol;
            }
            entry.last_seen = Utc::now();
            let entry = entry.clone();
            if changed {
                inner.mark_dirty();
            }
            return Ok(entry);
        }

        while inner.next_offset < inner.cidr.size.saturating_sub(1) {
            let fake_ip = inner
                .cidr
                .ip_at(inner.next_offset)
                .ok_or_else(|| anyhow!("fake CIDR exhausted"))?;
            inner.next_offset += 1;
            if inner.by_fake_ip.contains_key(&fake_ip) {
                continue;
            }

            let now = Utc::now();
            let entry = FakeDnsEntry {
                domain: key.clone(),
                fake_ip,
                real_ips,
                response_alias,
                upstream_authority,
                upstream_protocol,
                first_seen: now,
                last_seen: now,
            };
            inner.by_fake_ip.insert(fake_ip, key.clone());
            inner.by_domain.insert(key, entry.clone());
            inner.mark_dirty();
            return Ok(entry);
        }

        Err(anyhow!("fake CIDR exhausted"))
    }
}

impl RegistryInner {
    fn load_persisted_entries(&mut self) -> Result<()> {
        let Some(path) = &self.registry_path else {
            return Ok(());
        };
        if !path.exists() {
            return Ok(());
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read fake DNS registry {}", path.display()))?;
        let persisted: PersistedRegistry = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse fake DNS registry {}", path.display()))?;

        for mut entry in persisted.entries {
            entry.domain = normalize_domain(&entry.domain);
            let Some(offset) = self.cidr.offset_of(entry.fake_ip) else {
                continue;
            };
            if offset == 0 || self.by_fake_ip.contains_key(&entry.fake_ip) {
                continue;
            }
            if self.by_domain.contains_key(&entry.domain) {
                continue;
            }
            self.next_offset = self.next_offset.max(offset.saturating_add(1));
            self.by_fake_ip.insert(entry.fake_ip, entry.domain.clone());
            self.by_domain.insert(entry.domain.clone(), entry);
        }

        Ok(())
    }

    fn mark_dirty(&mut self) {
        if self.registry_path.is_some() {
            self.revision = self
                .revision
                .checked_add(1)
                .expect("fake DNS registry revision overflowed");
        }
    }

    fn persistence_snapshot(&self) -> Option<RegistrySnapshot> {
        if self.revision == self.persisted_revision {
            return None;
        }
        Some(RegistrySnapshot {
            path: self.registry_path.clone()?,
            entries: self.by_domain.values().cloned().collect(),
            revision: self.revision,
        })
    }
}

fn persist_snapshot(mut snapshot: RegistrySnapshot) -> Result<()> {
    let path = &snapshot.path;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create fake DNS registry dir {}",
                parent.display()
            )
        })?;
    }
    snapshot.entries.sort_by_key(|entry| entry.fake_ip);
    let payload = serde_json::to_vec_pretty(&PersistedRegistry {
        entries: snapshot.entries,
    })
    .context("failed to serialize fake DNS registry")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fake_dns_registry.json");
    let temporary_path = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        snapshot.revision
    ));

    let write_result = (|| -> Result<()> {
        let mut file = File::create(&temporary_path).with_context(|| {
            format!(
                "failed to create temporary fake DNS registry {}",
                temporary_path.display()
            )
        })?;
        file.write_all(&payload).with_context(|| {
            format!(
                "failed to write temporary fake DNS registry {}",
                temporary_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync temporary fake DNS registry {}",
                temporary_path.display()
            )
        })?;
        std::fs::rename(&temporary_path, path).with_context(|| {
            format!(
                "failed to replace fake DNS registry {} with {}",
                path.display(),
                temporary_path.display()
            )
        })
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    write_result
}

impl Ipv4Cidr {
    fn parse(value: &str) -> Result<Self> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or_else(|| anyhow!("CIDR must contain / prefix: {value}"))?;
        let ip = ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 CIDR address {ip}"))?;
        let prefix = prefix
            .parse::<u32>()
            .with_context(|| format!("invalid IPv4 CIDR prefix {prefix}"))?;
        if !(1..=30).contains(&prefix) {
            return Err(anyhow!("IPv4 CIDR prefix must be between 1 and 30"));
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(ip) & mask;
        let size = 1_u32 << (32 - prefix);
        Ok(Self { network, size })
    }

    fn ip_at(&self, offset: u32) -> Option<Ipv4Addr> {
        if offset >= self.size {
            return None;
        }
        Some(Ipv4Addr::from(self.network + offset))
    }

    fn offset_of(&self, ip: Ipv4Addr) -> Option<u32> {
        let value = u32::from(ip);
        if value < self.network {
            return None;
        }
        let offset = value - self.network;
        (offset < self.size).then_some(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allocates_stable_fake_ip() {
        let registry = FakeDnsRegistry::new("198.18.0.0/15").unwrap();
        let first = registry
            .allocate_or_update("Api.Example.Com.", vec![Ipv4Addr::new(1, 1, 1, 1)])
            .await
            .unwrap();
        let second = registry
            .allocate_or_update("api.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)])
            .await
            .unwrap();
        assert_eq!(first.fake_ip, second.fake_ip);
        assert_eq!(second.real_ips, vec![Ipv4Addr::new(2, 2, 2, 2)]);
    }

    #[tokio::test]
    async fn persists_entries_across_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        let first = registry
            .allocate_or_update("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)])
            .await
            .unwrap();
        assert!(!path.exists());
        assert!(registry.flush_if_dirty().await.unwrap());
        assert!(!registry.flush_if_dirty().await.unwrap());

        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        assert_eq!(
            registry.get_by_fake_ip(first.fake_ip).await.unwrap().domain,
            "api.example.com"
        );
        let second = registry
            .allocate_or_update("other.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)])
            .await
            .unwrap();
        assert_ne!(first.fake_ip, second.fake_ip);
    }

    #[tokio::test]
    async fn persists_response_alias_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        let entry = registry
            .register_response_alias(
                "K8S-CLUSTER.PLUTO-ECI.TRP.TEST.",
                Ipv4Addr::LOCALHOST,
                "127.0.0.1:8001",
                FakeDnsUpstreamProtocol::Http,
            )
            .await
            .unwrap();
        registry.flush_if_dirty().await.unwrap();

        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        let alias = registry
            .get_response_alias_by_domain("k8s-cluster.pluto-eci.trp.test")
            .await
            .unwrap();
        assert_eq!(alias.fake_ip, entry.fake_ip);
        assert_eq!(alias.real_ips, vec![Ipv4Addr::LOCALHOST]);
        assert_eq!(alias.upstream_authority.as_deref(), Some("127.0.0.1:8001"));
        assert_eq!(alias.upstream_protocol, Some(FakeDnsUpstreamProtocol::Http));
    }

    #[tokio::test]
    async fn allocates_raw_tcp_response_alias() {
        let registry = FakeDnsRegistry::new("198.18.0.0/15").unwrap();
        let entry = registry
            .register_raw_tcp_response_alias(
                "vintage-node-10-145-1-107.trp.test",
                Ipv4Addr::new(10, 145, 1, 107),
            )
            .await
            .unwrap();

        assert_eq!(entry.real_ips, vec![Ipv4Addr::new(10, 145, 1, 107)]);
        assert!(entry.response_alias);
        assert!(entry.upstream_authority.is_none());
        assert!(entry.upstream_protocol.is_none());
    }

    #[tokio::test]
    async fn keeps_bypassed_entries_for_stale_client_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        let entry = registry
            .allocate_or_update(
                "preview-wss-wegent.intra.demo.test",
                vec![Ipv4Addr::new(1, 1, 1, 1)],
            )
            .await
            .unwrap();
        registry.flush_if_dirty().await.unwrap();

        let registry = FakeDnsRegistry::load_or_new(
            "198.18.0.0/15",
            Some(&path),
            &["preview-wss-wegent.intra.demo.test".to_string()],
        )
        .unwrap();
        assert_eq!(
            registry.get_by_fake_ip(entry.fake_ip).await.unwrap().domain,
            "preview-wss-wegent.intra.demo.test"
        );
    }

    #[tokio::test]
    async fn does_not_flush_unchanged_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        registry
            .register_raw_tcp_response_alias(
                "vintage-node-10-145-1-107.trp.test",
                Ipv4Addr::new(10, 145, 1, 107),
            )
            .await
            .unwrap();
        assert!(registry.flush_if_dirty().await.unwrap());

        registry
            .register_raw_tcp_response_alias(
                "vintage-node-10-145-1-107.trp.test",
                Ipv4Addr::new(10, 145, 1, 107),
            )
            .await
            .unwrap();
        assert!(!registry.flush_if_dirty().await.unwrap());

        registry
            .register_raw_tcp_response_alias(
                "vintage-node-10-145-1-107.trp.test",
                Ipv4Addr::new(10, 145, 1, 108),
            )
            .await
            .unwrap();
        assert!(registry.flush_if_dirty().await.unwrap());
    }

    #[tokio::test]
    async fn retries_failed_flush_without_losing_dirty_state() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("registry");
        std::fs::write(&parent, b"not a directory").unwrap();
        let path = parent.join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        registry
            .allocate_or_update("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)])
            .await
            .unwrap();

        assert!(registry.flush_if_dirty().await.is_err());
        std::fs::remove_file(&parent).unwrap();
        std::fs::create_dir(&parent).unwrap();
        assert!(registry.flush_if_dirty().await.unwrap());
        assert!(!registry.flush_if_dirty().await.unwrap());
    }

    #[tokio::test]
    async fn update_after_snapshot_remains_dirty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        registry
            .allocate_or_update("first.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)])
            .await
            .unwrap();
        let snapshot_revision = registry
            .inner
            .lock()
            .await
            .persistence_snapshot()
            .unwrap()
            .revision;

        registry
            .allocate_or_update("second.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)])
            .await
            .unwrap();
        let mut inner = registry.inner.lock().await;
        inner.persisted_revision = inner.persisted_revision.max(snapshot_revision);
        let pending = inner.persistence_snapshot().unwrap();
        assert!(pending.revision > snapshot_revision);
        assert_eq!(pending.entries.len(), 2);
    }
}
