use chrono::{DateTime, Utc};

use crate::memcached::MemcachedWireProtocol;

const MAX_RELATIVE_EXPIRATION_SECONDS: u64 = 60 * 60 * 24 * 30;
const ABSOLUTE_EXPIRATION_TOLERANCE_SECONDS: u128 = 5;

pub(super) struct ArgumentSnapshot<'a> {
    pub(super) args: &'a [Vec<u8>],
    pub(super) extras: Option<&'a [u8]>,
    pub(super) observed_at: DateTime<Utc>,
}

pub(super) fn arguments_match(
    wire_protocol: MemcachedWireProtocol,
    command: &str,
    recorded: ArgumentSnapshot<'_>,
    actual: ArgumentSnapshot<'_>,
) -> bool {
    if recorded.args == actual.args && recorded.extras == actual.extras {
        return true;
    }
    match wire_protocol {
        MemcachedWireProtocol::Text => text_arguments_match(command, recorded, actual),
        MemcachedWireProtocol::Binary => binary_arguments_match(command, recorded, actual),
    }
}

fn text_arguments_match(
    command: &str,
    recorded: ArgumentSnapshot<'_>,
    actual: ArgumentSnapshot<'_>,
) -> bool {
    if recorded.extras != actual.extras || recorded.args.len() != actual.args.len() {
        return false;
    }
    let (index, valid_length) = match command.to_ascii_lowercase().as_str() {
        "set" | "add" | "replace" => (1, recorded.args.len() == 3),
        "cas" => (1, recorded.args.len() == 4),
        "touch" | "flush_all" => (0, recorded.args.len() == 1),
        "gat" | "gats" => (0, !recorded.args.is_empty()),
        _ => return false,
    };
    if !valid_length
        || !recorded
            .args
            .iter()
            .zip(actual.args)
            .enumerate()
            .all(|(position, (a, b))| position == index || a == b)
    {
        return false;
    }
    let Some(a) = parse_text_expiration(&recorded.args[index]) else {
        return false;
    };
    let Some(b) = parse_text_expiration(&actual.args[index]) else {
        return false;
    };
    expiration_matches(a, b, recorded.observed_at, actual.observed_at)
}

fn binary_arguments_match(
    command: &str,
    recorded: ArgumentSnapshot<'_>,
    actual: ArgumentSnapshot<'_>,
) -> bool {
    if recorded.args != actual.args {
        return false;
    }
    let (length, offset, arithmetic) = match command.to_ascii_lowercase().as_str() {
        "set" | "add" | "replace" => (8, 4, false),
        "touch" | "gat" | "flush" => (4, 0, false),
        "increment" | "decrement" => (20, 16, true),
        _ => return false,
    };
    let (Some(a), Some(b)) = (recorded.extras, actual.extras) else {
        return false;
    };
    if a.len() != length || b.len() != length || a[..offset] != b[..offset] {
        return false;
    }
    let a = u32::from_be_bytes(
        a[offset..offset + 4]
            .try_into()
            .expect("validated expiration size"),
    );
    let b = u32::from_be_bytes(
        b[offset..offset + 4]
            .try_into()
            .expect("validated expiration size"),
    );
    // In arithmetic, all-one bits mean do not create a missing key. It is a
    // protocol control value rather than an absolute Unix deadline.
    if arithmetic && (a == u32::MAX || b == u32::MAX) {
        return false;
    }
    expiration_matches(
        u64::from(a),
        u64::from(b),
        recorded.observed_at,
        actual.observed_at,
    )
}

fn parse_text_expiration(value: &[u8]) -> Option<u64> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn expiration_matches(
    recorded: u64,
    actual: u64,
    recorded_at: DateTime<Utc>,
    actual_at: DateTime<Utc>,
) -> bool {
    if recorded == actual {
        return true;
    }
    if recorded <= MAX_RELATIVE_EXPIRATION_SECONDS
        || actual <= MAX_RELATIVE_EXPIRATION_SECONDS
        || recorded_at == DateTime::UNIX_EPOCH
        || actual_at == DateTime::UNIX_EPOCH
    {
        return false;
    }
    let recorded_ttl = i128::from(recorded) - i128::from(recorded_at.timestamp());
    let actual_ttl = i128::from(actual) - i128::from(actual_at.timestamp());
    recorded_ttl.abs_diff(actual_ttl) <= ABSOLUTE_EXPIRATION_TOLERANCE_SECONDS
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn observed_at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).unwrap()
    }

    fn text_args(flags: &str, expiration: u64, bytes: usize) -> Vec<Vec<u8>> {
        vec![
            flags.as_bytes().to_vec(),
            expiration.to_string().into_bytes(),
            bytes.to_string().into_bytes(),
        ]
    }

    fn binary_extras(flags: u32, expiration: u32) -> Vec<u8> {
        [flags.to_be_bytes(), expiration.to_be_bytes()].concat()
    }

    type SnapshotParts<'a> = (&'a [Vec<u8>], Option<&'a [u8]>, DateTime<Utc>);

    fn matches(
        wire_protocol: MemcachedWireProtocol,
        command: &str,
        recorded: SnapshotParts<'_>,
        actual: SnapshotParts<'_>,
    ) -> bool {
        arguments_match(
            wire_protocol,
            command,
            ArgumentSnapshot {
                args: recorded.0,
                extras: recorded.1,
                observed_at: recorded.2,
            },
            ArgumentSnapshot {
                args: actual.0,
                extras: actual.1,
                observed_at: actual.2,
            },
        )
    }

    #[test]
    fn zero_and_relative_expirations_remain_exact() {
        let recorded_at = observed_at(1_700_000_000);
        let actual_at = observed_at(1_800_000_000);
        for expiration in [0, 86_400, MAX_RELATIVE_EXPIRATION_SECONDS] {
            assert!(expiration_matches(
                expiration,
                expiration,
                recorded_at,
                actual_at
            ));
            assert!(!expiration_matches(
                expiration,
                expiration + 1,
                recorded_at,
                actual_at
            ));
        }
    }

    #[test]
    fn absolute_expirations_compare_remaining_ttl_with_a_fixed_window() {
        let recorded_at = observed_at(1_700_000_000);
        let actual_at = observed_at(1_800_000_000);
        assert!(expiration_matches(
            1_700_086_400,
            1_800_086_405,
            recorded_at,
            actual_at
        ));
        assert!(!expiration_matches(
            1_700_086_400,
            1_800_086_406,
            recorded_at,
            actual_at
        ));
    }

    #[test]
    fn abtest_writeback_absolute_expiration_matches() {
        let recorded_at = Utc.timestamp_opt(1_786_725_060, 124_048_069).unwrap();
        let replay_at = Utc.timestamp_opt(1_786_774_620, 761_827_000).unwrap();

        assert!(expiration_matches(
            1_786_811_460,
            1_786_861_020,
            recorded_at,
            replay_at,
        ));
    }

    #[test]
    fn exact_absolute_deadlines_still_match() {
        assert!(expiration_matches(
            1_900_000_000,
            1_900_000_000,
            observed_at(1_700_000_000),
            observed_at(1_800_000_000)
        ));
    }

    #[test]
    fn relative_and_absolute_expirations_never_mix() {
        assert!(!expiration_matches(
            86_400,
            1_800_086_400,
            observed_at(1_700_000_000),
            observed_at(1_800_000_000)
        ));
    }

    #[test]
    fn text_set_relaxes_only_absolute_expiration() {
        let recorded_at = observed_at(1_700_000_000);
        let actual_at = observed_at(1_800_000_000);
        assert!(matches(
            MemcachedWireProtocol::Text,
            "set",
            (&text_args("7", 1_700_086_400, 5), None, recorded_at),
            (&text_args("7", 1_800_086_404, 5), None, actual_at),
        ));
        assert!(!matches(
            MemcachedWireProtocol::Text,
            "set",
            (&text_args("7", 1_700_086_400, 5), None, recorded_at),
            (&text_args("8", 1_800_086_400, 5), None, actual_at),
        ));
        assert!(!matches(
            MemcachedWireProtocol::Text,
            "set",
            (&text_args("7", 1_700_086_400, 5), None, recorded_at),
            (&text_args("7", 1_800_086_400, 6), None, actual_at),
        ));
    }

    #[test]
    fn binary_set_relaxes_only_absolute_expiration() {
        let recorded_at = observed_at(1_700_000_000);
        let actual_at = observed_at(1_800_000_000);
        assert!(matches(
            MemcachedWireProtocol::Binary,
            "set",
            (&[], Some(&binary_extras(7, 1_700_086_400)), recorded_at,),
            (&[], Some(&binary_extras(7, 1_800_086_405)), actual_at,),
        ));
        assert!(!matches(
            MemcachedWireProtocol::Binary,
            "set",
            (&[], Some(&binary_extras(7, 1_700_086_400)), recorded_at,),
            (&[], Some(&binary_extras(8, 1_800_086_400)), actual_at,),
        ));
    }

    #[test]
    fn every_supported_text_expiration_position_preserves_other_arguments() {
        let source = observed_at(1_700_000_000);
        let target = observed_at(1_800_000_000);
        for command in ["set", "add", "replace", "cas"] {
            let mut a = text_args("7", 1_700_000_060, 5);
            let mut b = text_args("7", 1_800_000_060, 5);
            if command == "cas" {
                a.push(b"42".to_vec());
                b.push(b"42".to_vec());
            }
            assert!(
                matches(
                    MemcachedWireProtocol::Text,
                    command,
                    (&a, None, source),
                    (&b, None, target)
                ),
                "{command}"
            );
            b[0] = b"8".to_vec();
            assert!(!matches(
                MemcachedWireProtocol::Text,
                command,
                (&a, None, source),
                (&b, None, target)
            ));
            if command == "cas" {
                b[0] = a[0].clone();
                b[3] = b"43".to_vec();
                assert!(!matches(
                    MemcachedWireProtocol::Text,
                    command,
                    (&a, None, source),
                    (&b, None, target)
                ));
            }
        }
        for command in ["touch", "gat", "gats", "flush_all"] {
            let mut a = vec![b"1700000060".to_vec()];
            let mut b = vec![b"1800000060".to_vec()];
            if matches!(command, "gat" | "gats") {
                a.push(b"second-key".to_vec());
                b.push(b"second-key".to_vec());
            }
            assert!(
                matches(
                    MemcachedWireProtocol::Text,
                    command,
                    (&a, None, source),
                    (&b, None, target)
                ),
                "{command}"
            );
            if a.len() > 1 {
                b[1] = b"another-key".to_vec();
                assert!(!matches(
                    MemcachedWireProtocol::Text,
                    command,
                    (&a, None, source),
                    (&b, None, target)
                ));
            }
        }
        assert!(!matches(
            MemcachedWireProtocol::Text,
            "incr",
            (&[b"1700000060".to_vec()], None, source),
            (&[b"1800000060".to_vec()], None, target)
        ));
        assert!(!matches(
            MemcachedWireProtocol::Text,
            "append",
            (&text_args("7", 1_700_000_060, 5), None, source),
            (&text_args("7", 1_800_000_060, 5), None, target)
        ));
    }

    #[test]
    fn supported_binary_expiration_layouts_and_arithmetic_control_are_distinct() {
        let source = observed_at(1_700_000_000);
        let target = observed_at(1_800_000_000);
        for command in [
            "set",
            "add",
            "replace",
            "touch",
            "gat",
            "flush",
            "increment",
            "decrement",
        ] {
            let extras = |expiration: u32| match command {
                "set" | "add" | "replace" => binary_extras(7, expiration),
                "increment" | "decrement" => [
                    1_u64.to_be_bytes().as_slice(),
                    10_u64.to_be_bytes().as_slice(),
                    expiration.to_be_bytes().as_slice(),
                ]
                .concat(),
                _ => expiration.to_be_bytes().to_vec(),
            };
            let a = extras(1_700_000_060);
            let mut b = extras(1_800_000_060);
            assert!(
                matches(
                    MemcachedWireProtocol::Binary,
                    command,
                    (&[], Some(&a), source),
                    (&[], Some(&b), target)
                ),
                "{command}"
            );
            if matches!(command, "increment" | "decrement") {
                b[7] = 2;
                assert!(!matches(
                    MemcachedWireProtocol::Binary,
                    command,
                    (&[], Some(&a), source),
                    (&[], Some(&b), target)
                ));
                let sentinel = extras(u32::MAX);
                let other = extras(u32::MAX - 1);
                assert!(!matches(
                    MemcachedWireProtocol::Binary,
                    command,
                    (&[], Some(&sentinel), source),
                    (&[], Some(&other), observed_at(source.timestamp() - 1))
                ));
                assert!(matches(
                    MemcachedWireProtocol::Binary,
                    command,
                    (&[], Some(&sentinel), source),
                    (&[], Some(&sentinel), target)
                ));
            }
        }
    }
}
