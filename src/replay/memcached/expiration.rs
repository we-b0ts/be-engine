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
    if !command.eq_ignore_ascii_case("set") {
        return false;
    }
    match wire_protocol {
        MemcachedWireProtocol::Text => text_set_arguments_match(
            recorded.args,
            actual.args,
            recorded.extras,
            actual.extras,
            recorded.observed_at,
            actual.observed_at,
        ),
        MemcachedWireProtocol::Binary => binary_set_arguments_match(
            recorded.args,
            actual.args,
            recorded.extras,
            actual.extras,
            recorded.observed_at,
            actual.observed_at,
        ),
    }
}

fn text_set_arguments_match(
    recorded_args: &[Vec<u8>],
    actual_args: &[Vec<u8>],
    recorded_extras: Option<&[u8]>,
    actual_extras: Option<&[u8]>,
    recorded_at: DateTime<Utc>,
    actual_at: DateTime<Utc>,
) -> bool {
    if recorded_extras != actual_extras || recorded_args.len() != 3 || actual_args.len() != 3 {
        return false;
    }
    if recorded_args[0] != actual_args[0] || recorded_args[2] != actual_args[2] {
        return false;
    }
    let Some(recorded_expiration) = parse_text_expiration(&recorded_args[1]) else {
        return false;
    };
    let Some(actual_expiration) = parse_text_expiration(&actual_args[1]) else {
        return false;
    };
    expiration_matches(
        recorded_expiration,
        actual_expiration,
        recorded_at,
        actual_at,
    )
}

fn binary_set_arguments_match(
    recorded_args: &[Vec<u8>],
    actual_args: &[Vec<u8>],
    recorded_extras: Option<&[u8]>,
    actual_extras: Option<&[u8]>,
    recorded_at: DateTime<Utc>,
    actual_at: DateTime<Utc>,
) -> bool {
    if recorded_args != actual_args {
        return false;
    }
    let (Some(recorded), Some(actual)) = (recorded_extras, actual_extras) else {
        return false;
    };
    if recorded.len() != 8 || actual.len() != 8 || recorded[..4] != actual[..4] {
        return false;
    }
    let recorded_expiration = u32::from_be_bytes(recorded[4..8].try_into().unwrap());
    let actual_expiration = u32::from_be_bytes(actual[4..8].try_into().unwrap());
    expiration_matches(
        u64::from(recorded_expiration),
        u64::from(actual_expiration),
        recorded_at,
        actual_at,
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
}
