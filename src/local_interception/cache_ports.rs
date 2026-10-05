use std::ffi::OsString;
use std::net::Ipv4Addr;

use crate::TRAFFIC_PROCESS_UID;
use anyhow::Result;

use super::{checked_output, checked_status, status_success};

const SOURCE_CHAIN: &str = "TRP_CACHE_SNAPSHOT";
const TARGET_CHAIN: &str = "TRP_CACHE_TARGET";

pub(super) fn up(
    ports: &[u16],
    tcp_port: u16,
    target_source_ip: Option<Ipv4Addr>,
    interception_listen_ip: Option<Ipv4Addr>,
) -> Result<()> {
    let result = try_up(ports, tcp_port, target_source_ip, interception_listen_ip);
    if result.is_err() {
        let _ = down();
    }
    result
}

fn try_up(
    ports: &[u16],
    tcp_port: u16,
    target_source_ip: Option<Ipv4Addr>,
    interception_listen_ip: Option<Ipv4Addr>,
) -> Result<()> {
    delete_jump_rules("OUTPUT", SOURCE_CHAIN)?;
    delete_jump_rules("PREROUTING", TARGET_CHAIN)?;
    reset_chain(SOURCE_CHAIN)?;
    for port in ports {
        let rule = match interception_listen_ip {
            Some(listen_ip) => dnat_rule(SOURCE_CHAIN, *port, listen_ip, tcp_port),
            None => redirect_rule(SOURCE_CHAIN, *port, tcp_port),
        };
        checked_status("iptables", rule)?;
    }
    checked_status("iptables", output_rule("-A"))?;
    if let Some(target_source_ip) = target_source_ip {
        reset_chain(TARGET_CHAIN)?;
        for port in ports {
            checked_status("iptables", redirect_rule(TARGET_CHAIN, *port, tcp_port))?;
        }
        checked_status("iptables", prerouting_rule("-A", target_source_ip))?;
    }
    Ok(())
}

pub(super) fn down() -> Result<()> {
    delete_jump_rules("OUTPUT", SOURCE_CHAIN)?;
    delete_jump_rules("PREROUTING", TARGET_CHAIN)?;
    remove_chain(SOURCE_CHAIN)?;
    remove_chain(TARGET_CHAIN)?;
    Ok(())
}

fn reset_chain(chain: &str) -> Result<()> {
    if !chain_exists(chain)? {
        checked_status("iptables", ["-t", "nat", "-N", chain])?;
    }
    checked_status("iptables", ["-t", "nat", "-F", chain])
}

fn remove_chain(chain: &str) -> Result<()> {
    if chain_exists(chain)? {
        checked_status("iptables", ["-t", "nat", "-F", chain])?;
        checked_status("iptables", ["-t", "nat", "-X", chain])?;
    }
    Ok(())
}

fn chain_exists(chain: &str) -> Result<bool> {
    status_success("iptables", ["-t", "nat", "-L", chain])
}

fn output_rule(operation: &str) -> Vec<OsString> {
    [
        "-t",
        "nat",
        operation,
        "OUTPUT",
        "-p",
        "tcp",
        "-m",
        "owner",
        "--uid-owner",
        &TRAFFIC_PROCESS_UID.to_string(),
        "-j",
        SOURCE_CHAIN,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn prerouting_rule(operation: &str, source_ip: Ipv4Addr) -> Vec<OsString> {
    [
        "-t".to_string(),
        "nat".to_string(),
        operation.to_string(),
        "PREROUTING".to_string(),
        "-s".to_string(),
        source_ip.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-j".to_string(),
        TARGET_CHAIN.to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn redirect_rule(chain: &str, port: u16, tcp_port: u16) -> Vec<OsString> {
    [
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        chain.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--dport".to_string(),
        port.to_string(),
        "-j".to_string(),
        "REDIRECT".to_string(),
        "--to-ports".to_string(),
        tcp_port.to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn dnat_rule(chain: &str, port: u16, listen_ip: Ipv4Addr, tcp_port: u16) -> Vec<OsString> {
    [
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        chain.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--dport".to_string(),
        port.to_string(),
        "-j".to_string(),
        "DNAT".to_string(),
        "--to-destination".to_string(),
        format!("{listen_ip}:{tcp_port}"),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn delete_jump_rules(parent_chain: &str, child_chain: &str) -> Result<()> {
    let output = checked_output("iptables", ["-t", "nat", "-S", parent_chain])?;
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(&format!("-j {child_chain}")))
        .collect::<Vec<_>>()
    {
        let mut args = line
            .split_whitespace()
            .map(OsString::from)
            .collect::<Vec<_>>();
        args[0] = OsString::from("-D");
        args.splice(0..0, [OsString::from("-t"), OsString::from("nat")]);
        checked_status("iptables", args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_only_configured_cache_ports_for_the_traffic_uid() {
        assert_eq!(
            output_rule("-A"),
            [
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-m",
                "owner",
                "--uid-owner",
                "998",
                "-j",
                "TRP_CACHE_SNAPSHOT",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        assert!(redirect_rule(SOURCE_CHAIN, 6379, 15001).ends_with(&[
            OsString::from("REDIRECT"),
            OsString::from("--to-ports"),
            OsString::from("15001"),
        ]));
        assert_eq!(
            prerouting_rule("-A", Ipv4Addr::new(172, 30, 0, 2)),
            [
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-s",
                "172.30.0.2",
                "-p",
                "tcp",
                "-j",
                "TRP_CACHE_TARGET",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        assert!(
            dnat_rule(SOURCE_CHAIN, 6379, Ipv4Addr::new(172, 30, 0, 1), 15001).ends_with(&[
                OsString::from("DNAT"),
                OsString::from("--to-destination"),
                OsString::from("172.30.0.1:15001"),
            ])
        );
    }
}
