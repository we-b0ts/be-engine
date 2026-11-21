use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};

use crate::AppState;
use crate::recording_control::RecordingListener;

pub use registry::FLUSH_INTERVAL as REGISTRY_FLUSH_INTERVAL;
pub use registry::{FakeDnsEntry, FakeDnsRegistry, FakeDnsUpstreamProtocol};
pub use traffic_engine_config::dns_mock::DomainMatcher;
use traffic_engine_config::dns_mock::normalize_domain;
use traffic_engine_config::dns_mock::registry;

#[derive(Debug)]
struct DnsQuestion {
    domain: String,
    qtype: u16,
    qclass: u16,
    question_end: usize,
}

pub async fn run(state: AppState) -> Result<()> {
    let config = state.config().dns_mock.clone();
    let socket = Arc::new(UdpSocket::bind(config.listen).await.with_context(|| {
        format!(
            "failed to bind DNS mock UDP {}; check `ss -lunp` for UDP port conflicts",
            config.listen
        )
    })?);
    state.mark_recording_listener_ready(RecordingListener::DnsMock);
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
    state
        .recorder()
        .observe_resolved_domain(&question.domain)
        .await?;
    let response = if question.qtype == 1 && question.qclass == 1 {
        if state.has_recording_upstream(&question.domain) {
            let entry = state
                .dns_registry()
                .allocate_or_update(&question.domain, vec![Ipv4Addr::LOCALHOST])
                .await?;
            build_fake_a_response(
                &query,
                question.question_end,
                entry.fake_ip,
                config.ttl_seconds,
            )?
        } else if let Some(entry) = state
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kubernetes_route_returns_fake_ip_without_contacting_real_dns() {
        let temp = tempfile::tempdir().unwrap();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = crate::AppConfig::default();
        config.dns_mock.enabled = true;
        config.tcp_gateway.enabled = true;
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        config.dns_mock.upstream_dns = upstream.local_addr().unwrap();
        config.dns_mock.registry_path = temp.path().join("dns.json");
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let host = "api.team.svc.cluster.local";
        config.upstream_routes.push(crate::UpstreamRouteConfig {
            host: host.into(),
            via: crate::UpstreamTransportConfig::KubernetesPortForward {
                namespace: "team".into(),
                service: "api".into(),
            },
        });
        let state = AppState::new(config).await.unwrap();
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        handle_query(
            server,
            state.clone(),
            query_for(host),
            client.local_addr().unwrap(),
        )
        .await
        .unwrap();
        let mut response = [0; 512];
        let received = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        let ips = parse_a_answers(&response[..received]).unwrap();
        assert_eq!(ips.len(), 1);
        assert_ne!(ips[0], Ipv4Addr::LOCALHOST);
        assert_eq!(
            state
                .dns_registry()
                .get_by_fake_ip(ips[0])
                .await
                .unwrap()
                .domain,
            host
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), upstream.recv(&mut response))
                .await
                .is_err()
        );
    }

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
