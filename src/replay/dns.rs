#[derive(Debug)]
pub(super) struct DnsQuestion {
    pub(super) domain: String,
    pub(super) qtype: u16,
    pub(super) qclass: u16,
    pub(super) question_end: usize,
}

pub(super) async fn handle_dns_query(
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<ReplayState>>,
    query: Vec<u8>,
    peer: SocketAddr,
) -> Result<()> {
    let question = parse_dns_question(&query)?;
    let fake_ip = if question.qtype == 1 && question.qclass == 1 {
        let state = state.lock().await;
        state
            .targets
            .iter()
            .find(|target| normalize_host(&target.host) == question.domain)
            .map(|target| target.fake_ip)
    } else {
        None
    };
    let response = match fake_ip {
        Some(fake_ip) => build_dns_a_response(&query, question.question_end, fake_ip)?,
        None => build_dns_empty_response(&query, question.question_end)?,
    };
    socket
        .send_to(&response, peer)
        .await
        .context("failed to send dependency replay DNS response")?;
    Ok(())
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes([
        *bytes
            .get(offset)
            .ok_or_else(|| anyhow!("u16 out of bounds"))?,
        *bytes
            .get(offset + 1)
            .ok_or_else(|| anyhow!("u16 out of bounds"))?,
    ]))
}

pub(super) fn parse_dns_question(packet: &[u8]) -> Result<DnsQuestion> {
    if packet.len() < 12 {
        return Err(anyhow!("DNS packet too short"));
    }
    let qdcount = read_be_u16(packet, 4)?;
    if qdcount == 0 {
        return Err(anyhow!("DNS packet has no questions"));
    }
    let (domain, offset) = read_dns_name(packet, 12)?;
    let qtype = read_be_u16(packet, offset)?;
    let qclass = read_be_u16(packet, offset + 2)?;
    Ok(DnsQuestion {
        domain: normalize_host(&domain),
        qtype,
        qclass,
        question_end: offset + 4,
    })
}

pub(super) fn build_dns_empty_response(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
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

pub(super) fn build_dns_a_response(
    query: &[u8],
    question_end: usize,
    fake_ip: Ipv4Addr,
) -> Result<Vec<u8>> {
    let mut response = build_dns_empty_response(query, question_end)?;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0xC00C_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&fake_ip.octets());
    Ok(response)
}

pub(super) fn read_dns_name(packet: &[u8], offset: usize) -> Result<(String, usize)> {
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

#[derive(Debug, Clone, Copy)]
pub(super) struct Ipv4Cidr {
    pub(super) network: u32,
    pub(super) size: u32,
}

impl Ipv4Cidr {
    pub(super) fn parse(value: &str) -> Result<Self> {
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

    pub(super) fn ip_at(&self, offset: u32) -> Option<Ipv4Addr> {
        if offset >= self.size {
            return None;
        }
        Some(Ipv4Addr::from(self.network + offset))
    }
}
use super::*;
