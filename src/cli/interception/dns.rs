use std::ffi::OsString;

use anyhow::Result;

use super::{
    DnsConfig, FIXED_USER, checked_output, checked_status, fixed_user_uid, status_success,
};
use crate::cli::output::{stdout, stdout_line};

const CHAIN: &str = "TRP_DNS";

pub(super) fn up(config: &DnsConfig) -> Result<()> {
    let result = try_up(config);
    if result.is_err() {
        let _ = down(config);
    }
    result
}

fn try_up(config: &DnsConfig) -> Result<()> {
    let uid = fixed_user_uid()?;
    delete_output_rules(uid)?;
    if !chain_exists()? {
        checked_status("iptables", ["-t", "nat", "-N", CHAIN])?;
    }
    checked_status("iptables", ["-t", "nat", "-F", CHAIN])?;
    for protocol in ["udp", "tcp"] {
        checked_status(
            "iptables",
            [
                OsString::from("-t"),
                OsString::from("nat"),
                OsString::from("-A"),
                OsString::from(CHAIN),
                OsString::from("-p"),
                OsString::from(protocol),
                OsString::from("--dport"),
                OsString::from("53"),
                OsString::from("-j"),
                OsString::from("DNAT"),
                OsString::from("--to-destination"),
                OsString::from(format!("{}:{}", config.dns_ip, config.dns_port)),
            ],
        )?;
        add_output_rule(protocol, uid)?;
    }
    stdout_line(format_args!(
        "local DNS capture enabled: *:53 -> {}:{}",
        config.dns_ip, config.dns_port
    ))?;
    stdout_line(format_args!("owner scope: {FIXED_USER} (uid {uid})"))?;
    Ok(())
}

pub(super) fn down(config: &DnsConfig) -> Result<()> {
    if let Ok(uid) = fixed_user_uid() {
        delete_output_rules(uid)?;
    } else {
        delete_output_rules_without_owner_lookup()?;
    }
    if chain_exists()? {
        checked_status("iptables", ["-t", "nat", "-F", CHAIN])?;
        checked_status("iptables", ["-t", "nat", "-X", CHAIN])?;
    }
    stdout_line(format_args!(
        "local DNS capture disabled: *:53 -> {}:{}",
        config.dns_ip, config.dns_port
    ))?;
    Ok(())
}

pub(super) fn status(config: &DnsConfig) -> Result<()> {
    let uid = fixed_user_uid()?;
    stdout_line(format_args!(
        "DNS listener expected at {}:{}",
        config.dns_ip, config.dns_port
    ))?;
    stdout_line(format_args!("Owner scope: {FIXED_USER} (uid {uid})"))?;
    let output = checked_output("iptables", ["-t", "nat", "-S", "OUTPUT"])?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.contains(&format!("-j {CHAIN}")) {
            stdout_line(format_args!("{line}"))?;
        }
    }
    if chain_exists()? {
        let output = checked_output("iptables", ["-t", "nat", "-S", CHAIN])?;
        stdout(format_args!("{}", String::from_utf8_lossy(&output.stdout)))?;
    }
    Ok(())
}

fn chain_exists() -> Result<bool> {
    status_success("iptables", ["-t", "nat", "-L", CHAIN])
}

fn output_rule(protocol: &str, uid: u32, operation: &str) -> Vec<OsString> {
    [
        "-t",
        "nat",
        operation,
        "OUTPUT",
        "-p",
        protocol,
        "-m",
        "owner",
        "--uid-owner",
        &uid.to_string(),
        "--dport",
        "53",
        "-j",
        CHAIN,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn add_output_rule(protocol: &str, uid: u32) -> Result<()> {
    if !status_success("iptables", output_rule(protocol, uid, "-C"))? {
        checked_status("iptables", output_rule(protocol, uid, "-A"))?;
    }
    Ok(())
}

fn delete_output_rules(uid: u32) -> Result<()> {
    for protocol in ["udp", "tcp"] {
        while status_success("iptables", output_rule(protocol, uid, "-C"))? {
            checked_status("iptables", output_rule(protocol, uid, "-D"))?;
        }
    }
    Ok(())
}

fn delete_output_rules_without_owner_lookup() -> Result<()> {
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
