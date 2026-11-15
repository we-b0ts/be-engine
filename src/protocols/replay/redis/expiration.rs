//! Adapt native absolute-expiration semantics to framework observation clocks.
use crate::value_contract::time::{ClockPair, DEFAULT_TOLERANCE};
use anyhow::Result;

pub(crate) fn normalize(
    command: &str,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    clocks: ClockPair,
) -> Result<Option<Vec<Vec<u8>>>> {
    traffic_protocol_redis::expiration::normalize(
        command,
        source,
        target,
        DEFAULT_TOLERANCE,
        |scale| {
            let (source, target) = clocks.require()?;
            Ok(if scale == 1000 {
                (source.timestamp_millis(), target.timestamp_millis())
            } else {
                (source.timestamp(), target.timestamp())
            })
        },
    )
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
