//! Protocol-declared absolute expirations preserve their remaining lifetime.
use crate::value_contract::time::ClockPair;
use anyhow::{Result, ensure};

/// Return a comparison copy with only an independently verified absolute
/// deadline normalized. Keys, payloads and every other option stay untouched.
pub(crate) fn normalize(
    command: &str,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    clocks: ClockPair,
) -> Result<Option<Vec<Vec<u8>>>> {
    if source == target {
        return Ok(None);
    }
    let selected = match command {
        "EXPIREAT" if matches!(source.len(), 2 | 3) => Some((1, 1_i128)),
        "PEXPIREAT" if matches!(source.len(), 2 | 3) => Some((1, 1000_i128)),
        "SET" if source.len() >= 4 => set_deadline(source),
        _ => None,
    };
    let Some((index, scale)) = selected else {
        return Ok(None);
    };
    ensure!(
        source.len() == target.len(),
        "Redis expiration argument count changed"
    );
    if source[index] == target[index] {
        return Ok(None);
    }
    // The SET option itself determines the unit. It cannot be selected by Target.
    if command == "SET" {
        ensure!(
            source[index - 1] == target[index - 1],
            "Redis expiration mode changed"
        );
    }
    let parse = |bytes: &[u8]| -> Result<i128> {
        let value = std::str::from_utf8(bytes)?.parse::<i64>()?;
        Ok(i128::from(value))
    };
    let source_deadline = parse(&source[index])?;
    let target_deadline = parse(&target[index])?;
    let (source_at, target_at) = clocks.require()?;
    let source_clock = if scale == 1000 {
        source_at.timestamp_millis()
    } else {
        source_at.timestamp()
    };
    let target_clock = if scale == 1000 {
        target_at.timestamp_millis()
    } else {
        target_at.timestamp()
    };
    let source_remaining = source_deadline - i128::from(source_clock);
    let target_remaining = target_deadline - i128::from(target_clock);
    ensure!(
        (source_remaining > 0) == (target_remaining > 0)
            && source_remaining.abs_diff(target_remaining) <= (5 * scale) as u128,
        "Redis absolute expiration changed its remaining lifetime"
    );
    let mut normalized = target.to_vec();
    normalized[index] = source[index].clone();
    Ok(Some(normalized))
}

fn set_deadline(args: &[Vec<u8>]) -> Option<(usize, i128)> {
    let mut result = None;
    let mut index = 2;
    while index < args.len() {
        let flag = args[index].as_slice();
        if flag.eq_ignore_ascii_case(b"EXAT") || flag.eq_ignore_ascii_case(b"PXAT") {
            if result.is_some() || index + 1 >= args.len() {
                return None;
            }
            result = Some((
                index + 1,
                if flag.eq_ignore_ascii_case(b"PXAT") {
                    1000
                } else {
                    1
                },
            ));
            index += 2;
        } else if flag.eq_ignore_ascii_case(b"EX")
            || flag.eq_ignore_ascii_case(b"PX")
            || flag.eq_ignore_ascii_case(b"KEEPTTL")
        {
            // Conflicting or relative expiry options cannot acquire permission.
            return None;
        } else if flag.eq_ignore_ascii_case(b"NX")
            || flag.eq_ignore_ascii_case(b"XX")
            || flag.eq_ignore_ascii_case(b"GET")
        {
            index += 1;
        } else {
            return None;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<Vec<u8>> {
        values.iter().map(|s| s.as_bytes().to_vec()).collect()
    }
    fn clocks() -> ClockPair {
        ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        }
    }

    #[test]
    fn absolute_deadlines_are_native_and_preserve_other_arguments() {
        for (command, source, target) in [
            (
                "SET",
                args(&["key", "payload", "NX", "EXAT", "1060"]),
                args(&["key", "different", "NX", "EXAT", "2060"]),
            ),
            (
                "SET",
                args(&["key", "payload", "PXAT", "1060123"]),
                args(&["key", "payload", "PXAT", "2060123"]),
            ),
            (
                "EXPIREAT",
                args(&["key", "1060", "GT"]),
                args(&["key", "2060", "GT"]),
            ),
            (
                "PEXPIREAT",
                args(&["key", "1060123"]),
                args(&["key", "2060123"]),
            ),
        ] {
            let normalized = normalize(command, &source, &target, clocks())
                .unwrap()
                .unwrap();
            let index = if command == "SET" {
                normalized.len() - 1
            } else {
                1
            };
            assert_eq!(normalized[index], source[index]);
            for (i, value) in normalized.iter().enumerate() {
                if i != index {
                    assert_eq!(*value, target[i]);
                }
            }
        }
    }

    #[test]
    fn changed_lifetime_missing_clocks_and_mode_changes_fail() {
        let source = args(&["key", "payload", "EXAT", "1060"]);
        assert!(
            normalize(
                "SET",
                &source,
                &args(&["key", "payload", "EXAT", "2100"]),
                clocks()
            )
            .is_err()
        );
        assert!(
            normalize(
                "SET",
                &source,
                &args(&["key", "payload", "EXAT", "2060"]),
                ClockPair::default()
            )
            .is_err()
        );
        assert!(
            normalize(
                "SET",
                &source,
                &args(&["key", "payload", "PXAT", "2060"]),
                clocks()
            )
            .is_err()
        );
        assert!(
            normalize(
                "EXPIREAT",
                &args(&["key", "1001"]),
                &args(&["key", "1999"]),
                clocks()
            )
            .is_err()
        );
    }

    #[test]
    fn relative_and_equal_deadlines_need_no_policy_or_clock() {
        for command in ["SETEX", "PSETEX", "EXPIRE", "PEXPIRE"] {
            assert!(
                normalize(
                    command,
                    &args(&["key", "60"]),
                    &args(&["key", "61"]),
                    clocks()
                )
                .unwrap()
                .is_none()
            );
        }
        let source = args(&["key", "payload", "EXAT", "1060"]);
        assert!(
            normalize("SET", &source, &source, ClockPair::default())
                .unwrap()
                .is_none()
        );
        assert!(
            normalize(
                "SET",
                &args(&["key", "a", "EX", "60"]),
                &args(&["key", "b", "EX", "61"]),
                clocks()
            )
            .unwrap()
            .is_none()
        );
    }
}
