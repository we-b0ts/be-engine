use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, anyhow};

use crate::recorder::ProcessInfo;

#[derive(Debug, Clone, Copy)]
struct TcpSocketEntry {
    local: SocketAddr,
    remote: SocketAddr,
    state: u8,
    inode: u64,
}

pub fn lookup_tcp_process(
    local_addr: SocketAddr,
    candidate_remote_addrs: &[SocketAddr],
) -> Option<ProcessInfo> {
    let entries = read_tcp_entries().ok()?;
    let mut exact_inodes = HashSet::new();
    let mut port_fallback_inodes = HashSet::new();
    let mut unique_local_port_inodes = HashSet::new();

    for entry in entries {
        if entry.state != TCP_STATE_LISTEN && entry.local.port() == local_addr.port() {
            unique_local_port_inodes.insert(entry.inode);
        }
        if !candidate_remote_addrs.contains(&entry.remote) {
            continue;
        }
        if entry.local == local_addr {
            exact_inodes.insert(entry.inode);
        } else if entry.local.port() == local_addr.port() {
            port_fallback_inodes.insert(entry.inode);
        }
    }

    find_process_for_inodes(&exact_inodes)
        .or_else(|| find_process_for_inodes(&port_fallback_inodes))
        .or_else(|| {
            if unique_local_port_inodes.len() == 1 {
                find_process_for_inodes(&unique_local_port_inodes)
            } else {
                None
            }
        })
}

pub fn lookup_listening_process(addr: SocketAddr) -> Option<ProcessInfo> {
    let entries = read_tcp_entries().ok()?;
    let inodes = entries
        .into_iter()
        .filter(|entry| entry.state == TCP_STATE_LISTEN)
        .filter(|entry| entry.local.port() == addr.port())
        .filter(|entry| listen_addr_matches(entry.local, addr))
        .map(|entry| entry.inode)
        .collect::<HashSet<_>>();
    find_process_for_inodes(&inodes)
}

pub fn process_label(process: &ProcessInfo) -> String {
    let name = process
        .comm
        .as_deref()
        .or(process.exe.as_deref())
        .unwrap_or("unknown");
    match process.cmdline.as_deref() {
        Some(cmdline) if !cmdline.is_empty() => {
            format!("pid={} name={} cmdline={}", process.pid, name, cmdline)
        }
        _ => format!("pid={} name={}", process.pid, name),
    }
}

fn read_tcp_entries() -> Result<Vec<TcpSocketEntry>> {
    let mut entries = Vec::new();
    read_tcp4_entries("/proc/net/tcp", &mut entries)?;
    read_tcp6_entries("/proc/net/tcp6", &mut entries)?;
    Ok(entries)
}

fn read_tcp4_entries(path: &str, entries: &mut Vec<TcpSocketEntry>) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    for line in raw.lines().skip(1) {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() <= 9 {
            continue;
        }
        let local = parse_tcp4_addr(parts[1])?;
        let remote = parse_tcp4_addr(parts[2])?;
        let state = u8::from_str_radix(parts[3], 16)
            .with_context(|| format!("invalid TCP state {}", parts[3]))?;
        let inode = parts[9]
            .parse::<u64>()
            .with_context(|| format!("invalid TCP inode {}", parts[9]))?;
        if inode != 0 {
            entries.push(TcpSocketEntry {
                local,
                remote,
                state,
                inode,
            });
        }
    }
    Ok(())
}

const TCP_STATE_LISTEN: u8 = 0x0A;

fn listen_addr_matches(listener: SocketAddr, target: SocketAddr) -> bool {
    listener.ip().is_unspecified() || listener.ip() == target.ip()
}

fn parse_tcp4_addr(value: &str) -> Result<SocketAddr> {
    let (ip_hex, port_hex) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid TCP address {value}"))?;
    let raw_ip = u32::from_str_radix(ip_hex, 16)
        .with_context(|| format!("invalid TCP IPv4 address {ip_hex}"))?;
    let ip = Ipv4Addr::from(raw_ip.to_le_bytes());
    let port = u16::from_str_radix(port_hex, 16)
        .with_context(|| format!("invalid TCP port {port_hex}"))?;
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

fn read_tcp6_entries(path: &str, entries: &mut Vec<TcpSocketEntry>) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    for line in raw.lines().skip(1) {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() <= 9 {
            continue;
        }
        let local = parse_tcp6_addr(parts[1])?;
        let remote = parse_tcp6_addr(parts[2])?;
        let state = u8::from_str_radix(parts[3], 16)
            .with_context(|| format!("invalid TCP state {}", parts[3]))?;
        let inode = parts[9]
            .parse::<u64>()
            .with_context(|| format!("invalid TCP inode {}", parts[9]))?;
        if inode != 0 {
            entries.push(TcpSocketEntry {
                local,
                remote,
                state,
                inode,
            });
        }
    }
    Ok(())
}

fn parse_tcp6_addr(value: &str) -> Result<SocketAddr> {
    let (ip_hex, port_hex) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("invalid TCP address {value}"))?;
    if ip_hex.len() != 32 {
        anyhow::bail!("invalid TCP IPv6 address {ip_hex}");
    }

    let mut bytes = [0_u8; 16];
    for (chunk_index, chunk) in ip_hex.as_bytes().chunks_exact(8).enumerate() {
        let chunk = std::str::from_utf8(chunk)
            .with_context(|| format!("invalid TCP IPv6 address {ip_hex}"))?;
        let raw = u32::from_str_radix(chunk, 16)
            .with_context(|| format!("invalid TCP IPv6 address {ip_hex}"))?;
        bytes[chunk_index * 4..chunk_index * 4 + 4].copy_from_slice(&raw.to_le_bytes());
    }

    let port = u16::from_str_radix(port_hex, 16)
        .with_context(|| format!("invalid TCP port {port_hex}"))?;
    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
}

fn find_process_for_inodes(inodes: &HashSet<u64>) -> Option<ProcessInfo> {
    if inodes.is_empty() {
        return None;
    }

    for entry in fs::read_dir("/proc").ok()? {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let inode = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok());
            if inode.is_some_and(|inode| inodes.contains(&inode)) {
                return Some(read_process_info(pid));
            }
        }
    }

    None
}

fn read_process_info(pid: u32) -> ProcessInfo {
    let base = format!("/proc/{pid}");
    let comm = fs::read_to_string(format!("{base}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let cmdline = fs::read(format!("{base}/cmdline"))
        .ok()
        .map(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|value| !value.is_empty());
    let exe = fs::read_link(format!("{base}/exe"))
        .ok()
        .map(|path| path.display().to_string());

    ProcessInfo {
        pid,
        comm,
        cmdline,
        exe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn parses_proc_tcp_ipv4_addresses() {
        let addr = parse_tcp4_addr("0100007F:0035").unwrap();
        assert_eq!(addr, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_proc_tcp_ipv6_addresses() {
        let loopback = parse_tcp6_addr("00000000000000000000000001000000:1C03").unwrap();
        assert_eq!(loopback, "[::1]:7171".parse::<SocketAddr>().unwrap());

        let unspecified = parse_tcp6_addr("00000000000000000000000000000000:1C03").unwrap();
        assert_eq!(unspecified, "[::]:7171".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn looks_up_current_process_for_local_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();

        let process = lookup_tcp_process(peer_addr, &[server.local_addr().unwrap()])
            .expect("current process should own client socket");
        assert_eq!(process.pid, std::process::id());

        drop(client);
        drop(server);
    }

    #[tokio::test]
    async fn falls_back_to_unique_local_port_for_redirected_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).await.unwrap();
        let (server, peer_addr) = listener.accept().await.unwrap();
        let redirected_peer =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7)), peer_addr.port());
        let fake_remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7)), 443);

        let process = lookup_tcp_process(redirected_peer, &[fake_remote])
            .expect("unique local source port should identify current process");
        assert_eq!(process.pid, std::process::id());

        drop(client);
        drop(server);
    }

    #[tokio::test]
    async fn looks_up_current_process_for_listening_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let process = lookup_listening_process(listener.local_addr().unwrap())
            .expect("current process should own listening socket");
        assert_eq!(process.pid, std::process::id());
        drop(listener);
    }
}
