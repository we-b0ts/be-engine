use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};

use crate::AppState;

mod bypass;
pub(crate) use bypass::DomainMatcher;
use bypass::normalize_domain;

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
}

struct RegistryInner {
    cidr: Ipv4Cidr,
    next_offset: u32,
    by_domain: HashMap<String, FakeDnsEntry>,
    by_fake_ip: HashMap<Ipv4Addr, String>,
    registry_path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct PersistedRegistry {
    entries: Vec<FakeDnsEntry>,
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: u32,
    size: u32,
}

#[derive(Debug)]
struct DnsQuestion {
    domain: String,
    qtype: u16,
    qclass: u16,
    question_end: usize,
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
        };
        inner.load_persisted_entries()?;

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
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

    async fn allocate_or_update(
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
            entry.real_ips = real_ips;
            entry.response_alias = response_alias;
            entry.upstream_authority = upstream_authority;
            entry.upstream_protocol = upstream_protocol;
            entry.last_seen = Utc::now();
            let entry = entry.clone();
            inner.persist_entries()?;
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
            inner.persist_entries()?;
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

    fn persist_entries(&self) -> Result<()> {
        let Some(path) = &self.registry_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create fake DNS registry dir {}",
                    parent.display()
                )
            })?;
        }
        let mut entries = self.by_domain.values().cloned().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.fake_ip);
        let payload = serde_json::to_vec_pretty(&PersistedRegistry { entries })
            .context("failed to serialize fake DNS registry")?;
        std::fs::write(path, payload)
            .with_context(|| format!("failed to write fake DNS registry {}", path.display()))
    }
}

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config().dns_mock.clone();
    let socket = Arc::new(UdpSocket::bind(config.listen).await.with_context(|| {
        format!(
            "failed to bind DNS mock UDP {}; check `ss -lunp` for UDP port conflicts",
            config.listen
        )
    })?);
    info!(
        listen = %config.listen,
        upstream_dns = %config.upstream_dns,
        fake_cidr = %config.fake_cidr,
        bypass_exact_domains = state.dns_bypass_matcher().exact_count(),
        bypass_suffixes = state.dns_bypass_matcher().suffix_count(),
        bypass_wildcards = state.dns_bypass_matcher().wildcard_count(),
        static_hosts = config.hosts.len(),
        "DNS mock listening"
    );

    let mut buf = vec![0_u8; 4096];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("failed to receive DNS query")?;
        let query = buf[..len].to_vec();
        let state = state.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_query(socket, state, query, peer).await {
                warn!(error = %err, peer = %peer, "failed to handle DNS query");
            }
        });
    }
}

async fn handle_query(
    socket: Arc<UdpSocket>,
    state: AppState,
    query: Vec<u8>,
    peer: SocketAddr,
) -> Result<()> {
    let config = state.config().dns_mock.clone();
    let question = parse_question(&query)?;
    let response = if question.qtype == 1 && question.qclass == 1 {
        if let Some(entry) = state
            .dns_registry()
            .get_response_alias_by_domain(&question.domain)
            .await
        {
            build_fake_a_response(
                &query,
                question.question_end,
                entry.fake_ip,
                config.ttl_seconds,
            )?
        } else if let Some(real_ips) = static_hosts_for_domain(&config.hosts, &question.domain) {
            let entry = state
                .dns_registry()
                .allocate_or_update(&question.domain, real_ips)
                .await?;
            build_fake_a_response(
                &query,
                question.question_end,
                entry.fake_ip,
                config.ttl_seconds,
            )?
        } else {
            let upstream_response = query_upstream(&query, config.upstream_dns).await?;
            if state.dns_bypass_matcher().matches(&question.domain) {
                upstream_response
            } else {
                let real_ips = parse_a_answers(&upstream_response).unwrap_or_default();
                if real_ips.is_empty() {
                    build_empty_response(&query, question.question_end)?
                } else {
                    let entry = state
                        .dns_registry()
                        .allocate_or_update(&question.domain, real_ips)
                        .await?;
                    build_fake_a_response(
                        &query,
                        question.question_end,
                        entry.fake_ip,
                        config.ttl_seconds,
                    )?
                }
            }
        }
    } else {
        build_empty_response(&query, question.question_end)?
    };

    socket
        .send_to(&response, peer)
        .await
        .context("failed to send DNS response")?;
    Ok(())
}

async fn query_upstream(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind upstream DNS socket")?;
    socket
        .send_to(query, upstream)
        .await
        .with_context(|| format!("failed to send DNS query to {upstream}"))?;
    let mut buf = vec![0_u8; 4096];
    let len = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .context("upstream DNS query timed out")?
        .context("failed to receive upstream DNS response")?;
    buf.truncate(len);
    Ok(buf)
}

fn parse_question(packet: &[u8]) -> Result<DnsQuestion> {
    if packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }
    let qdcount = read_u16(packet, 4)?;
    if qdcount == 0 {
        return Err(anyhow!("DNS packet has no questions"));
    }
    let (domain, offset) = read_name(packet, 12)?;
    let qtype = read_u16(packet, offset)?;
    let qclass = read_u16(packet, offset + 2)?;
    Ok(DnsQuestion {
        domain: normalize_domain(&domain),
        qtype,
        qclass,
        question_end: offset + 4,
    })
}

fn parse_a_answers(packet: &[u8]) -> Result<Vec<Ipv4Addr>> {
    if packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }
    let qdcount = read_u16(packet, 4)? as usize;
    let ancount = read_u16(packet, 6)? as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(packet, offset)?;
        offset = next + 4;
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(packet, offset)?;
        offset = next;
        let rr_type = read_u16(packet, offset)?;
        let rr_class = read_u16(packet, offset + 2)?;
        let rdlen = read_u16(packet, offset + 8)? as usize;
        offset += 10;
        let rdata = packet
            .get(offset..offset + rdlen)
            .ok_or_else(|| anyhow!("DNS answer rdata out of bounds"))?;
        if rr_type == 1 && rr_class == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        offset += rdlen;
    }
    Ok(out)
}

fn static_hosts_for_domain(
    hosts: &BTreeMap<String, Vec<Ipv4Addr>>,
    domain: &str,
) -> Option<Vec<Ipv4Addr>> {
    let key = normalize_domain(domain);
    hosts
        .iter()
        .find(|(domain, ips)| normalize_domain(domain) == key && !ips.is_empty())
        .map(|(_, ips)| ips)
        .filter(|ips| !ips.is_empty())
        .cloned()
}

fn build_empty_response(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(query.get(0..2).ok_or_else(|| anyhow!("missing DNS id"))?);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(
        query
            .get(12..question_end)
            .ok_or_else(|| anyhow!("missing DNS question"))?,
    );
    Ok(response)
}

fn build_fake_a_response(
    query: &[u8],
    question_end: usize,
    fake_ip: Ipv4Addr,
    ttl_seconds: u32,
) -> Result<Vec<u8>> {
    let mut response = build_empty_response(query, question_end)?;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0xC00C_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl_seconds.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&fake_ip.octets());
    Ok(response)
}

fn read_name(packet: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed_end = None;
    let mut jumps = 0;

    loop {
        let len = *packet
            .get(cursor)
            .ok_or_else(|| anyhow!("DNS name out of bounds"))?;
        if len & 0xC0 == 0xC0 {
            let next = *packet
                .get(cursor + 1)
                .ok_or_else(|| anyhow!("DNS compression pointer out of bounds"))?;
            let pointer = (((len & 0x3F) as usize) << 8) | next as usize;
            consumed_end.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            if jumps > 16 {
                return Err(anyhow!("too many DNS compression jumps"));
            }
            continue;
        }
        if len == 0 {
            let end = consumed_end.unwrap_or(cursor + 1);
            return Ok((labels.join("."), end));
        }
        cursor += 1;
        let label = packet
            .get(cursor..cursor + len as usize)
            .ok_or_else(|| anyhow!("DNS label out of bounds"))?;
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor += len as usize;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes([
        *packet
            .get(offset)
            .ok_or_else(|| anyhow!("u16 out of bounds"))?,
        *packet
            .get(offset + 1)
            .ok_or_else(|| anyhow!("u16 out of bounds"))?,
    ]))
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

    fn query_for(domain: &str) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234_u16.to_be_bytes());
        query.extend_from_slice(&0x0100_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    #[test]
    fn parses_dns_question() {
        let query = query_for("api.example.com");
        let question = parse_question(&query).unwrap();
        assert_eq!(question.domain, "api.example.com");
        assert_eq!(question.qtype, 1);
    }

    #[test]
    fn builds_fake_a_response() {
        let query = query_for("api.example.com");
        let question = parse_question(&query).unwrap();
        let response = build_fake_a_response(
            &query,
            question.question_end,
            Ipv4Addr::new(198, 18, 0, 1),
            60,
        )
        .unwrap();
        assert_eq!(read_u16(&response, 6).unwrap(), 1);
        assert_eq!(&response[response.len() - 4..], &[198, 18, 0, 1]);
    }

    #[tokio::test]
    async fn registry_allocates_stable_fake_ip() {
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
    async fn registry_persists_entries_across_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake_dns_registry.json");
        let registry = FakeDnsRegistry::load_or_new("198.18.0.0/15", Some(&path), &[]).unwrap();
        let first = registry
            .allocate_or_update("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)])
            .await
            .unwrap();

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
    async fn registry_persists_response_alias_metadata() {
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
    async fn registry_keeps_bypassed_entries_for_stale_client_cache() {
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

    #[test]
    fn static_hosts_match_normalized_domain_names() {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "Db-10-185-28-119.Test.".to_string(),
            vec![Ipv4Addr::new(10, 185, 28, 119)],
        );

        assert_eq!(
            static_hosts_for_domain(&hosts, "db-10-185-28-119.test"),
            Some(vec![Ipv4Addr::new(10, 185, 28, 119)])
        );
        assert_eq!(
            static_hosts_for_domain(&hosts, "DB-10-185-28-119.TEST."),
            Some(vec![Ipv4Addr::new(10, 185, 28, 119)])
        );
        assert!(static_hosts_for_domain(&hosts, "other.test").is_none());
    }
}
