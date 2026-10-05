use crate::ReplayEgressCounterSnapshot;
use anyhow::{Context, Result, ensure};

use super::checked_output;
use crate::command_output::stdout_line;

pub(super) fn read() -> Result<()> {
    let (ipv4_packets, v4_generation) = family("iptables")?;
    let (ipv6_packets, v6_generation) = family("ip6tables")?;
    ensure!(
        v4_generation == v6_generation,
        "Replay firewall rules changed during counter sampling"
    );
    stdout_line(format_args!(
        "{}",
        serde_json::to_string(&ReplayEgressCounterSnapshot {
            generation: v4_generation,
            ipv4_packets,
            ipv6_packets,
        })?
    ))
}

fn family(program: &str) -> Result<(u64, String)> {
    let output = checked_output(program, ["-w", "1", "-nvxL", "TRP_REPLAY_EGRESS"])?;
    parse(&String::from_utf8(output.stdout)?)
}

fn parse(output: &str) -> Result<(u64, String)> {
    let rows = output
        .lines()
        .filter(|line| line.split_whitespace().nth(2) == Some("REJECT"))
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "expected one Replay egress REJECT rule");
    let row = rows[0];
    let packets = row
        .split_whitespace()
        .next()
        .context("REJECT counter missing")?
        .parse()?;
    let generation = row
        .split_once("/* ")
        .and_then(|(_, tail)| tail.split_once(" */"))
        .map(|(value, _)| value)
        .filter(|value| value.starts_with("trp-egress-"))
        .context("Replay egress generation missing")?;
    Ok((packets, generation.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_exact_counter_and_rejects_missing_or_duplicate_rules() {
        let row = "1234567 456 REJECT all -- * * 0.0.0.0/0 0.0.0.0/0 /* trp-egress-epoch */ reject-with icmp-port-unreachable";
        assert_eq!(parse(row).unwrap(), (1234567, "trp-egress-epoch".into()));
        assert!(parse("0 0 RETURN all -- * * 0/0 0/0").is_err());
        assert!(parse(&format!("{row}\n{row}")).is_err());
    }
}
