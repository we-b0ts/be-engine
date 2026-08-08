use std::ffi::OsString;

use anyhow::Result;
use traffic_e2e::TRAFFIC_PROCESS_UID;

use super::{checked_output, checked_status, status_success};

const CHAIN: &str = "TRP_CACHE_SNAPSHOT";

pub(super) fn up(ports: &[u16], tcp_port: u16) -> Result<()> {
    let result = try_up(ports, tcp_port);
    if result.is_err() {
        let _ = down();
    }
    result
}

fn try_up(ports: &[u16], tcp_port: u16) -> Result<()> {
    delete_output_rules()?;
    if !chain_exists()? {
        checked_status("iptables", ["-t", "nat", "-N", CHAIN])?;
    }
    checked_status("iptables", ["-t", "nat", "-F", CHAIN])?;
    for port in ports {
        checked_status("iptables", redirect_rule(*port, tcp_port))?;
    }
    checked_status("iptables", output_rule("-A"))?;
    Ok(())
}

pub(super) fn down() -> Result<()> {
    delete_output_rules()?;
    if chain_exists()? {
        checked_status("iptables", ["-t", "nat", "-F", CHAIN])?;
        checked_status("iptables", ["-t", "nat", "-X", CHAIN])?;
    }
    Ok(())
}

fn chain_exists() -> Result<bool> {
    status_success("iptables", ["-t", "nat", "-L", CHAIN])
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
        CHAIN,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn redirect_rule(port: u16, tcp_port: u16) -> Vec<OsString> {
    [
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        CHAIN.to_string(),
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

fn delete_output_rules() -> Result<()> {
    let output = checked_output("iptables", ["-t", "nat", "-S", "OUTPUT"])?;
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains(&format!("-j {CHAIN}")))
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
                CHAIN,
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        assert!(redirect_rule(6379, 15001).ends_with(&[
            OsString::from("REDIRECT"),
            OsString::from("--to-ports"),
            OsString::from("15001"),
        ]));
    }
}
