use std::ffi::OsString;

use anyhow::Result;
use traffic_e2e::TRAFFIC_PROCESS_UID;

use super::{FIXED_USER, FakeIpConfig, checked_output, checked_status, status_success};
use crate::cli::output::stdout_line;

pub(super) fn up(config: &FakeIpConfig) -> Result<()> {
    let result = try_up(config);
    if result.is_err() {
        let _ = down(config);
    }
    result
}

fn try_up(config: &FakeIpConfig) -> Result<()> {
    delete_rules(config)?;
    if !route_exists(&config.fake_cidr)? {
        checked_status(
            "ip",
            ["route", "add", "local", &config.fake_cidr, "dev", "lo"],
        )?;
    }
    if config.tcp {
        add_rule("tcp", config.tcp_port, &config.fake_cidr)?;
    }
    if config.udp {
        add_rule("udp", config.udp_port, &config.fake_cidr)?;
    }
    stdout_line(format_args!(
        "fake IP redirect enabled: {} tcp={}:{} udp={}:{}",
        config.fake_cidr, config.tcp, config.tcp_port, config.udp, config.udp_port
    ))?;
    stdout_line(format_args!(
        "owner scope: {FIXED_USER} (uid {TRAFFIC_PROCESS_UID})"
    ))?;
    Ok(())
}

pub(super) fn down(config: &FakeIpConfig) -> Result<()> {
    delete_rules(config)?;
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
    stdout_line(format_args!("Fake IP CIDR: {}", config.fake_cidr))?;
    stdout_line(format_args!(
        "Owner scope: {FIXED_USER} (uid {TRAFFIC_PROCESS_UID})"
    ))?;
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

fn rule(operation: &str, protocol: &str, port: u16, cidr: &str) -> Vec<OsString> {
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
        OsString::from(TRAFFIC_PROCESS_UID.to_string()),
        OsString::from("-d"),
        OsString::from(cidr),
        OsString::from("-j"),
        OsString::from("REDIRECT"),
        OsString::from("--to-ports"),
        OsString::from(port.to_string()),
    ]
    .into()
}

fn add_rule(protocol: &str, port: u16, cidr: &str) -> Result<()> {
    if !status_success("iptables", rule("-C", protocol, port, cidr))? {
        checked_status("iptables", rule("-A", protocol, port, cidr))?;
    }
    Ok(())
}

fn delete_rules(config: &FakeIpConfig) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ip_rule_is_scoped_to_the_container_traffic_uid() {
        assert!(
            rule("-A", "tcp", 15001, "198.18.0.0/15")
                .windows(2)
                .any(|values| values == ["--uid-owner", "998"])
        );
    }
}
