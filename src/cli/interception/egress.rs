use std::ffi::OsString;

use anyhow::Result;

use super::{checked_output, checked_status, fixed_user_uid, status_success};
use crate::cli::output::stdout_line;

const CHAIN: &str = "TRP_REPLAY_EGRESS";

pub(super) fn up() -> Result<()> {
    let uid = fixed_user_uid()?;
    let result = try_up(uid);
    if result.is_err() {
        let _ = down_for_uid(Some(uid));
    }
    result
}

fn try_up(uid: u32) -> Result<()> {
    for program in ["iptables", "ip6tables"] {
        delete_output_rules(program, Some(uid))?;
        if !chain_exists(program)? {
            checked_status(program, ["-N", CHAIN])?;
        }
        checked_status(program, ["-F", CHAIN])?;
        checked_status(program, ["-A", CHAIN, "-o", "lo", "-j", "RETURN"])?;
        checked_status(program, ["-A", CHAIN, "-j", "REJECT"])?;
        checked_status(program, output_rule(uid, "-I"))?;
    }
    Ok(())
}

pub(super) fn down() -> Result<()> {
    down_for_uid(fixed_user_uid().ok())
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

fn down_for_uid(uid: Option<u32>) -> Result<()> {
    for program in ["iptables", "ip6tables"] {
        delete_output_rules(program, uid)?;
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

fn output_rule(uid: u32, operation: &str) -> Vec<OsString> {
    [
        operation,
        "OUTPUT",
        "-m",
        "owner",
        "--uid-owner",
        &uid.to_string(),
        "-j",
        CHAIN,
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn delete_output_rules(program: &str, uid: Option<u32>) -> Result<()> {
    if let Some(uid) = uid {
        while status_success(program, output_rule(uid, "-C"))? {
            checked_status(program, output_rule(uid, "-D"))?;
        }
        return Ok(());
    }
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
            output_rule(998, "-I"),
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
