use std::ffi::OsString;

use anyhow::Result;
use traffic_e2e::TRAFFIC_PROCESS_UID;

use super::{checked_output, checked_status, status_success};
use crate::cli::output::stdout_line;

const CHAIN: &str = "TRP_REPLAY_EGRESS";

pub(super) fn up() -> Result<()> {
    let result = try_up();
    if result.is_err() {
        let _ = down_rules();
    }
    result
}

fn try_up() -> Result<()> {
    for program in ["iptables", "ip6tables"] {
        delete_output_rules(program)?;
        if !chain_exists(program)? {
            checked_status(program, ["-N", CHAIN])?;
        }
        checked_status(program, ["-F", CHAIN])?;
        checked_status(program, ["-A", CHAIN, "-o", "lo", "-j", "RETURN"])?;
        checked_status(program, ["-A", CHAIN, "-j", "REJECT"])?;
        checked_status(program, output_rule("-I"))?;
    }
    Ok(())
}

pub(super) fn down() -> Result<()> {
    down_rules()
}

pub(super) fn status() -> Result<()> {
    for program in ["iptables", "ip6tables"] {
        for chain in ["OUTPUT", CHAIN] {
            if chain != CHAIN || chain_exists(program)? {
                let output = checked_output(program, ["-S", chain])?;
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if chain == CHAIN || line.contains(&format!("-j {CHAIN}")) {
                        stdout_line(format_args!("{program}: {line}"))?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn down_rules() -> Result<()> {
    for program in ["iptables", "ip6tables"] {
        delete_output_rules(program)?;
        if chain_exists(program)? {
            checked_status(program, ["-F", CHAIN])?;
            checked_status(program, ["-X", CHAIN])?;
        }
    }
    Ok(())
}

fn chain_exists(program: &str) -> Result<bool> {
    status_success(program, ["-L", CHAIN])
}

fn output_rule(operation: &str) -> Vec<OsString> {
    [
        operation,
        "OUTPUT",
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

fn delete_output_rules(program: &str) -> Result<()> {
    let output = checked_output(program, ["-S", "OUTPUT"])?;
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
        checked_status(program, args)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_rule_is_scoped_to_the_fixed_uid() {
        assert_eq!(
            output_rule("-I"),
            [
                "-I",
                "OUTPUT",
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
    }
}
