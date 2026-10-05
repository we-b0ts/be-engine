use std::ffi::OsString;
use std::net::Ipv4Addr;

use crate::TRAFFIC_PROCESS_UID;
use anyhow::{Context, Result, ensure};

use super::{DnsConfig, FIXED_USER, checked_output, checked_status, status_success};
use crate::command_output::{stdout, stdout_line};

mod conntrack;

const CHAIN: &str = "TRP_DNS";
const ZONE_CHAIN: &str = "TRP_DNS_ZONE";
// Reserved for local DNS interception. UID is not part of a conntrack tuple,
// so owner-scoped NAT alone can reuse another process's unredirected flow.
const CONNTRACK_ZONE: u16 = 4053;
const PROTOCOLS: [&str; 2] = ["udp", "tcp"];

pub(super) fn up(config: &DnsConfig) -> Result<()> {
    let listener = listener_ip(config)?;
    let result = try_up(config, listener).and_then(|()| {
        stdout_line(format_args!(
            "local DNS capture enabled: *:53 -> {listener}:{} (conntrack zone {CONNTRACK_ZONE})",
            config.dns_port
        ))?;
        stdout_line(format_args!(
            "owner scope: {FIXED_USER} (uid {TRAFFIC_PROCESS_UID})"
        ))
    });
    if let Err(error) = result {
        return match down_rules() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "DNS interception rollback also failed: {cleanup:#}"
            ))),
        };
    }
    Ok(())
}

fn try_up(config: &DnsConfig, listener: Ipv4Addr) -> Result<()> {
    // A previous listener may have left NAT state in the reserved zone. Remove
    // it before admitting queries; changing iptables does not change old NAT.
    down_rules()?;
    checked_status("iptables", ["-t", "nat", "-N", CHAIN])?;
    checked_status("iptables", ["-t", "raw", "-N", ZONE_CHAIN])?;
    checked_status("iptables", zone_rule())
        .context("DNS interception requires kernel/iptables support for conntrack zones")?;
    for protocol in PROTOCOLS {
        checked_status("iptables", redirect_rule(config, listener, protocol))?;
    }
    for rule in activation_rules(listener, config.dns_port) {
        checked_status("iptables", rule)?;
    }
    Ok(())
}

pub(super) fn down(config: &DnsConfig) -> Result<()> {
    down_rules()?;
    stdout_line(format_args!(
        "local DNS capture disabled: *:53 -> {}:{}",
        config.dns_ip, config.dns_port
    ))?;
    Ok(())
}

fn down_rules() -> Result<()> {
    // Attempt every stage even if one fails, including partial up() rollback.
    let errors = [
        remove_chain("nat", CHAIN),
        remove_chain("raw", ZONE_CHAIN),
        conntrack::clear_zone(CONNTRACK_ZONE)
            .context("failed to clear the reserved DNS conntrack zone"),
    ]
    .into_iter()
    .filter_map(Result::err)
    .map(|error| format!("{error:#}"))
    .collect::<Vec<_>>();
    ensure!(
        errors.is_empty(),
        "DNS interception cleanup failed: {}",
        errors.join("; ")
    );
    Ok(())
}

pub(super) fn status(config: &DnsConfig) -> Result<()> {
    stdout_line(format_args!(
        "DNS listener expected at {}:{}",
        config.dns_ip, config.dns_port
    ))?;
    stdout_line(format_args!(
        "Owner scope: {FIXED_USER} (uid {TRAFFIC_PROCESS_UID}); conntrack zone {CONNTRACK_ZONE}"
    ))?;
    for (table, chain) in [("nat", CHAIN), ("raw", ZONE_CHAIN)] {
        let output = checked_output("iptables", ["-t", table, "-S", "OUTPUT"])?;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if jumps_to(line, chain) {
                stdout_line(format_args!("{table}: {line}"))?;
            }
        }
        if chain_exists(table, chain)? {
            let output = checked_output("iptables", ["-t", table, "-S", chain])?;
            stdout(format_args!("{}", String::from_utf8_lossy(&output.stdout)))?;
        }
    }
    Ok(())
}

fn listener_ip(config: &DnsConfig) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = config
        .dns_ip
        .parse()
        .context("DNS interception listener must be an IPv4 address")?;
    ensure!(
        config.dns_port != 0,
        "DNS interception listener port must not be zero"
    );
    // recv_from/send_to on a wildcard UDP socket does not preserve the query's
    // destination IP. A non-loopback peer can then receive a reply from an IP
    // that cannot match the redirected connection's reverse NAT tuple.
    ensure!(
        !ip.is_unspecified(),
        "DNS interception requires a concrete IPv4 listener address; use 127.0.0.153 instead of 0.0.0.0"
    );
    Ok(ip)
}

fn chain_exists(table: &str, chain: &str) -> Result<bool> {
    status_success("iptables", ["-t", table, "-L", chain])
}

fn activation_rules(listener: Ipv4Addr, port: u16) -> Vec<Vec<OsString>> {
    // Enable query classification last: a query entering the reserved zone
    // before NAT is ready would leave an unredirected entry there after up().
    PROTOCOLS
        .into_iter()
        .map(|protocol| reply_zone_rule(listener, port, protocol))
        .chain(
            PROTOCOLS
                .into_iter()
                .map(|protocol| output_rule(protocol, "-A")),
        )
        .chain(PROTOCOLS.into_iter().map(query_zone_rule))
        .collect()
}

fn output_rule(protocol: &str, operation: &str) -> Vec<OsString> {
    args(&[
        "-t",
        "nat",
        operation,
        "OUTPUT",
        "-p",
        protocol,
        "-m",
        "owner",
        "--uid-owner",
        &TRAFFIC_PROCESS_UID.to_string(),
        "--dport",
        "53",
        "-j",
        CHAIN,
    ])
}

fn query_zone_rule(protocol: &str) -> Vec<OsString> {
    args(&[
        "-t",
        "raw",
        "-I",
        "OUTPUT",
        "-p",
        protocol,
        "-m",
        "owner",
        "--uid-owner",
        &TRAFFIC_PROCESS_UID.to_string(),
        "--dport",
        "53",
        "-j",
        ZONE_CHAIN,
    ])
}

fn reply_zone_rule(ip: Ipv4Addr, port: u16, protocol: &str) -> Vec<OsString> {
    args(&[
        "-t",
        "raw",
        "-I",
        "OUTPUT",
        "-p",
        protocol,
        "-s",
        &ip.to_string(),
        "--sport",
        &port.to_string(),
        "-j",
        ZONE_CHAIN,
    ])
}

fn zone_rule() -> Vec<OsString> {
    args(&[
        "-t",
        "raw",
        "-A",
        ZONE_CHAIN,
        "-j",
        "CT",
        "--zone",
        &CONNTRACK_ZONE.to_string(),
    ])
}

fn redirect_rule(config: &DnsConfig, ip: Ipv4Addr, protocol: &str) -> Vec<OsString> {
    args(&[
        "-t",
        "nat",
        "-A",
        CHAIN,
        "-p",
        protocol,
        "--dport",
        "53",
        "-j",
        "DNAT",
        "--to-destination",
        &format!("{ip}:{}", config.dns_port),
    ])
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn remove_chain(table: &str, chain: &str) -> Result<()> {
    let output = checked_output("iptables", ["-t", table, "-S", "OUTPUT"])?;
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| jumps_to(line, chain))
    {
        let mut arguments = line
            .split_whitespace()
            .map(OsString::from)
            .collect::<Vec<_>>();
        arguments[0] = OsString::from("-D");
        arguments.splice(0..0, args(&["-t", table]));
        checked_status("iptables", arguments)?;
    }
    if chain_exists(table, chain)? {
        checked_status("iptables", ["-t", table, "-F", chain])?;
        checked_status("iptables", ["-t", table, "-X", chain])?;
    }
    Ok(())
}

fn jumps_to(line: &str, chain: &str) -> bool {
    line.split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|tokens| tokens == ["-j", chain])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_queries_keep_fixed_owner_scope_in_nat_and_raw_tables() {
        for protocol in PROTOCOLS {
            for rule in [output_rule(protocol, "-A"), query_zone_rule(protocol)] {
                assert!(rule.windows(2).any(|v| v == ["--uid-owner", "998"]));
                assert!(rule.windows(2).any(|v| v == ["--dport", "53"]));
            }
        }
    }

    #[test]
    fn mock_replies_use_listener_address_and_port_without_an_owner_filter() {
        for protocol in PROTOCOLS {
            let rule = reply_zone_rule("127.0.0.154".parse().unwrap(), 15353, protocol);
            assert!(rule.windows(2).any(|v| v == ["-s", "127.0.0.154"]));
            assert!(rule.windows(2).any(|v| v == ["--sport", "15353"]));
            assert!(!rule.iter().any(|v| v == "--uid-owner"));
            assert!(rule.windows(2).any(|v| v == ["-j", ZONE_CHAIN]));
        }
    }

    #[test]
    fn wildcard_listener_is_rejected_before_redirecting_queries() {
        let config = DnsConfig {
            dns_ip: "0.0.0.0".into(),
            dns_port: 4053,
        };
        assert!(
            listener_ip(&config)
                .unwrap_err()
                .to_string()
                .contains("concrete IPv4")
        );
    }

    #[test]
    fn invalid_listener_is_rejected_before_touching_rules() {
        for config in [
            DnsConfig {
                dns_ip: "::1".into(),
                dns_port: 4053,
            },
            DnsConfig {
                dns_ip: "127.0.0.153".into(),
                dns_port: 0,
            },
        ] {
            assert!(listener_ip(&config).is_err());
        }
    }

    #[test]
    fn cleanup_only_matches_the_exact_owned_chain() {
        assert!(jumps_to("-A OUTPUT -j TRP_DNS", CHAIN));
        assert!(!jumps_to("-A OUTPUT -j TRP_DNS_OTHER", CHAIN));
        assert!(!jumps_to("-A OUTPUT -j TRP_DNS_ZONE", CHAIN));
    }

    #[test]
    fn query_zone_is_enabled_only_after_reply_classification_and_nat() {
        let rules = activation_rules(Ipv4Addr::LOCALHOST, 4053);
        for protocol in PROTOCOLS {
            let position =
                |expected: Vec<OsString>| rules.iter().position(|rule| *rule == expected).unwrap();
            let query = position(query_zone_rule(protocol));
            for dependency_protocol in PROTOCOLS {
                assert!(
                    position(reply_zone_rule(
                        Ipv4Addr::LOCALHOST,
                        4053,
                        dependency_protocol
                    )) < query
                );
                assert!(position(output_rule(dependency_protocol, "-A")) < query);
            }
        }
    }
}
