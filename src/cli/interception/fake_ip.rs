use std::ffi::OsString;

use anyhow::Result;

use super::{
    FIXED_USER, FakeIpConfig, checked_output, checked_status, fixed_user_uid, status_success,
};
use crate::cli::output::stdout_line;

pub(super) fn up(config: &FakeIpConfig) -> Result<()> {
    let result = try_up(config);
    if result.is_err() {
        let _ = down(config);
    }
    result
}

fn try_up(config: &FakeIpConfig) -> Result<()> {
    let uid = fixed_user_uid()?;
    delete_rules(config, uid)?;
    if !route_exists(&config.fake_cidr)? {
        checked_status(
            "ip",
            ["route", "add", "local", &config.fake_cidr, "dev", "lo"],
        )?;
    }
    if config.tcp {
        add_rule("tcp", config.tcp_port, &config.fake_cidr, uid)?;
    }
    if config.udp {
        add_rule("udp", config.udp_port, &config.fake_cidr, uid)?;
    }
    stdout_line(format_args!(
        "fake IP redirect enabled: {} tcp={}:{} udp={}:{}",
        config.fake_cidr, config.tcp, config.tcp_port, config.udp, config.udp_port
    ))?;
    stdout_line(format_args!("owner scope: {FIXED_USER} (uid {uid})"))?;
    Ok(())
}

pub(super) fn down(config: &FakeIpConfig) -> Result<()> {
    if let Ok(uid) = fixed_user_uid() {
        delete_rules(config, uid)?;
    } else {
        delete_rules_without_owner_lookup(config)?;
    }
    if route_exists(&config.fake_cidr)? {
        checked_status(
            "ip",
            ["route", "del", "local", &config.fake_cidr, "dev", "lo"],
        )?;
    }
    stdout_line(format_args!(
        "fake IP redirect disabled: {}",
        config.fake_cidr
    ))?;
    Ok(())
}

pub(super) fn status(config: &FakeIpConfig) -> Result<()> {
    let uid = fixed_user_uid()?;
    stdout_line(format_args!("Fake IP CIDR: {}", config.fake_cidr))?;
    stdout_line(format_args!("Owner scope: {FIXED_USER} (uid {uid})"))?;
    stdout_line(format_args!(
        "Local route installed: {}",
        route_exists(&config.fake_cidr)?
    ))?;
    let output = checked_output("iptables", ["-t", "nat", "-S", "OUTPUT"])?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.contains(&config.fake_cidr) && line.contains("-j REDIRECT") {
            stdout_line(format_args!("{line}"))?;
        }
    }
    Ok(())
}

fn route_exists(cidr: &str) -> Result<bool> {
    let output = checked_output("ip", ["route", "show", "table", "local"])?;
    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split_whitespace()
            .collect::<Vec<_>>()
            .starts_with(&["local", cidr, "dev", "lo"])
    }))
}

fn rule(operation: &str, protocol: &str, port: u16, cidr: &str, uid: u32) -> Vec<OsString> {
    [
        OsString::from("-t"),
        OsString::from("nat"),
        OsString::from(operation),
        OsString::from("OUTPUT"),
        OsString::from("-p"),
        OsString::from(protocol),
        OsString::from("-m"),
        OsString::from("owner"),
        OsString::from("--uid-owner"),
        OsString::from(uid.to_string()),
        OsString::from("-d"),
        OsString::from(cidr),
        OsString::from("-j"),
        OsString::from("REDIRECT"),
        OsString::from("--to-ports"),
        OsString::from(port.to_string()),
    ]
    .into()
}

fn add_rule(protocol: &str, port: u16, cidr: &str, uid: u32) -> Result<()> {
    if !status_success("iptables", rule("-C", protocol, port, cidr, uid))? {
        checked_status("iptables", rule("-A", protocol, port, cidr, uid))?;
    }
    Ok(())
}

fn delete_rules(config: &FakeIpConfig, uid: u32) -> Result<()> {
    for (protocol, port) in [("tcp", config.tcp_port), ("udp", config.udp_port)] {
        while status_success(
            "iptables",
            rule("-C", protocol, port, &config.fake_cidr, uid),
        )? {
            checked_status(
                "iptables",
                rule("-D", protocol, port, &config.fake_cidr, uid),
            )?;
        }
    }
    Ok(())
}

fn delete_rules_without_owner_lookup(config: &FakeIpConfig) -> Result<()> {
    let output = checked_output("iptables", ["-t", "nat", "-S", "OUTPUT"])?;
    let tcp_port = config.tcp_port.to_string();
    let udp_port = config.udp_port.to_string();
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| {
            line.contains(&config.fake_cidr)
                && line.contains("-j REDIRECT")
                && (line.ends_with(&format!("--to-ports {tcp_port}"))
                    || line.ends_with(&format!("--to-ports {udp_port}")))
        })
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
