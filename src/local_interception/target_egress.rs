use std::ffi::OsString;
use std::net::Ipv4Addr;

use anyhow::Result;

use super::{checked_output, checked_status, status_success};

const CHAIN: &str = "TRP_TARGET_EGRESS";

pub(super) fn up(target_source_ip: Ipv4Addr) -> Result<()> {
    let result = try_up(target_source_ip);
    if result.is_err() {
        let _ = down();
    }
    result
}

fn try_up(target_source_ip: Ipv4Addr) -> Result<()> {
    delete_jump_rules("filter", "FORWARD")?;
    delete_jump_rules("nat", "POSTROUTING")?;
    reset_chain("filter")?;
    reset_chain("nat")?;

    checked_status("iptables", forward_to_target_rule(target_source_ip))?;
    checked_status("iptables", forward_from_target_rule(target_source_ip))?;
    checked_status("iptables", masquerade_rule())?;
    checked_status(
        "iptables",
        jump_rule("filter", "FORWARD", "-s", target_source_ip, "-I"),
    )?;
    checked_status(
        "iptables",
        jump_rule("filter", "FORWARD", "-d", target_source_ip, "-I"),
    )?;
    checked_status(
        "iptables",
        jump_rule("nat", "POSTROUTING", "-s", target_source_ip, "-A"),
    )?;
    Ok(())
}

pub(super) fn down() -> Result<()> {
    delete_jump_rules("filter", "FORWARD")?;
    delete_jump_rules("nat", "POSTROUTING")?;
    remove_chain("filter")?;
    remove_chain("nat")?;
    Ok(())
}

fn reset_chain(table: &str) -> Result<()> {
    if !chain_exists(table)? {
        checked_status("iptables", ["-t", table, "-N", CHAIN])?;
    }
    checked_status("iptables", ["-t", table, "-F", CHAIN])
}

fn remove_chain(table: &str) -> Result<()> {
    if chain_exists(table)? {
        checked_status("iptables", ["-t", table, "-F", CHAIN])?;
        checked_status("iptables", ["-t", table, "-X", CHAIN])?;
    }
    Ok(())
}

fn chain_exists(table: &str) -> Result<bool> {
    status_success("iptables", ["-t", table, "-L", CHAIN])
}

fn jump_rule(
    table: &str,
    parent: &str,
    direction: &str,
    target_source_ip: Ipv4Addr,
    operation: &str,
) -> Vec<OsString> {
    [
        "-t".to_string(),
        table.to_string(),
        operation.to_string(),
        parent.to_string(),
        direction.to_string(),
        format!("{target_source_ip}/32"),
        "-j".to_string(),
        CHAIN.to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn forward_from_target_rule(target_source_ip: Ipv4Addr) -> Vec<OsString> {
    [
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        CHAIN.to_string(),
        "-s".to_string(),
        format!("{target_source_ip}/32"),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn forward_to_target_rule(target_source_ip: Ipv4Addr) -> Vec<OsString> {
    [
        "-t".to_string(),
        "filter".to_string(),
        "-A".to_string(),
        CHAIN.to_string(),
        "-d".to_string(),
        format!("{target_source_ip}/32"),
        "-m".to_string(),
        "conntrack".to_string(),
        "--ctstate".to_string(),
        "ESTABLISHED,RELATED".to_string(),
        "-j".to_string(),
        "ACCEPT".to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn masquerade_rule() -> Vec<OsString> {
    ["-t", "nat", "-A", CHAIN, "-j", "MASQUERADE"]
        .into_iter()
        .map(OsString::from)
        .collect()
}

fn delete_jump_rules(table: &str, parent_chain: &str) -> Result<()> {
    let output = checked_output("iptables", ["-t", table, "-S", parent_chain])?;
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
        args.splice(0..0, [OsString::from("-t"), OsString::from(table)]);
        checked_status("iptables", args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_forwarding_and_masquerade_to_the_comparison_target() {
        let target = Ipv4Addr::new(172, 30, 0, 2);

        assert_eq!(
            jump_rule("nat", "POSTROUTING", "-s", target, "-A"),
            [
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "172.30.0.2/32",
                "-j",
                "TRP_TARGET_EGRESS",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        assert!(
            jump_rule("filter", "FORWARD", "-s", target, "-I")
                .windows(2)
                .any(|fields| fields == [OsString::from("-s"), OsString::from("172.30.0.2/32")])
        );
        assert!(
            jump_rule("filter", "FORWARD", "-d", target, "-I")
                .windows(2)
                .any(|fields| fields == [OsString::from("-d"), OsString::from("172.30.0.2/32")])
        );
        assert!(forward_from_target_rule(target).ends_with(&[OsString::from("ACCEPT")]));
        assert!(forward_to_target_rule(target).windows(2).any(|fields| {
            fields
                == [
                    OsString::from("--ctstate"),
                    OsString::from("ESTABLISHED,RELATED"),
                ]
        }));
        assert!(masquerade_rule().ends_with(&[OsString::from("MASQUERADE")]));
    }
}
