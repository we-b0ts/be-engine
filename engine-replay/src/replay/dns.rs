use super::*;
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Cidr {
    pub network: u32,
    pub size: u32,
}

impl Ipv4Cidr {
    pub fn parse(value: &str) -> Result<Self> {
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

    pub fn ip_at(&self, offset: u32) -> Option<Ipv4Addr> {
        if offset >= self.size {
            return None;
        }
        Some(Ipv4Addr::from(self.network + offset))
    }

    pub fn offset_of(&self, ip: Ipv4Addr) -> Option<u32> {
        let value = u32::from(ip);
        if value < self.network {
            return None;
        }
        let offset = value - self.network;
        (offset < self.size).then_some(offset)
    }
}
