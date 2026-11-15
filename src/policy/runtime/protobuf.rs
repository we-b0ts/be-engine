use chrono::{DateTime, Utc};

pub(super) fn matches_with_timestamp_fields(
    recorded: &[u8],
    actual: &[u8],
    timestamp_fields: &[u32],
    recorded_observed_at: DateTime<Utc>,
    actual_observed_at: DateTime<Utc>,
) -> Result<(), String> {
    let mut recorded = FieldCursor::new(recorded, timestamp_fields, recorded_observed_at);
    let mut actual = FieldCursor::new(actual, timestamp_fields, actual_observed_at);

    loop {
        match (recorded.next_stable()?, actual.next_stable()?) {
            (Some(left), Some(right)) if left == right => {}
            (None, None) => break,
            _ => {
                return Err(
                    "stable protobuf fields in the Memcached value did not match".to_string(),
                );
            }
        }
    }

    recorded.ensure_all_timestamp_fields_seen()?;
    actual.ensure_all_timestamp_fields_seen()?;
    Ok(())
}

struct FieldCursor<'a> {
    remaining: &'a [u8],
    timestamp_fields: &'a [u32],
    observed_at: DateTime<Utc>,
    seen: Vec<(u32, bool)>,
}

impl<'a> FieldCursor<'a> {
    fn new(payload: &'a [u8], timestamp_fields: &'a [u32], observed_at: DateTime<Utc>) -> Self {
        Self {
            remaining: payload,
            timestamp_fields,
            observed_at,
            seen: timestamp_fields
                .iter()
                .map(|number| (*number, false))
                .collect(),
        }
    }

    fn next_stable(&mut self) -> Result<Option<&'a [u8]>, String> {
        while !self.remaining.is_empty() {
            let original = self.remaining;
            let (key, key_bytes) = read_varint(original)?;
            let number = u32::try_from(key >> 3)
                .map_err(|_| "protobuf field number is out of range".to_string())?;
            if number == 0 || number >= 1 << 29 {
                return Err("protobuf field number is invalid".to_string());
            }
            let wire_type = (key & 0x07) as u8;
            let (encoded_value, field_bytes) = field_value(&original[key_bytes..], wire_type)?;
            let encoded_len = key_bytes
                .checked_add(field_bytes)
                .ok_or_else(|| "protobuf field length overflow".to_string())?;
            let raw = &original[..encoded_len];
            self.remaining = &original[encoded_len..];

            if self.timestamp_fields.contains(&number) {
                let seen = self
                    .seen
                    .iter_mut()
                    .find(|(candidate, _)| *candidate == number)
                    .expect("timestamp field initialized from the same map");
                if seen.1 {
                    return Err(format!(
                        "protobuf timestamp field {number} occurs more than once"
                    ));
                }
                seen.1 = true;
                if wire_type != 0 {
                    return Err(format!(
                        "protobuf timestamp field {number} must use the varint wire type"
                    ));
                }
                let (timestamp, consumed) = read_varint(encoded_value)?;
                if consumed != encoded_value.len() {
                    return Err(format!(
                        "protobuf timestamp field {number} has an invalid varint"
                    ));
                }
                validate_timestamp(number, timestamp, self.observed_at)?;
                continue;
            }
            return Ok(Some(raw));
        }
        Ok(None)
    }

    fn ensure_all_timestamp_fields_seen(&self) -> Result<(), String> {
        if let Some((number, _)) = self.seen.iter().find(|(_, seen)| !seen) {
            return Err(format!(
                "protobuf timestamp field {number} is missing from the Memcached value"
            ));
        }
        Ok(())
    }
}

fn field_value(input: &[u8], wire_type: u8) -> Result<(&[u8], usize), String> {
    match wire_type {
        0 => {
            let (_, len) = read_varint(input)?;
            Ok((&input[..len], len))
        }
        1 => fixed_value(input, 8),
        2 => {
            let (len, prefix_len) = read_varint(input)?;
            let len = usize::try_from(len)
                .map_err(|_| "protobuf length-delimited field is too large".to_string())?;
            let total = prefix_len
                .checked_add(len)
                .ok_or_else(|| "protobuf length-delimited field overflow".to_string())?;
            if input.len() < total {
                return Err("protobuf length-delimited field is truncated".to_string());
            }
            Ok((&input[..total], total))
        }
        5 => fixed_value(input, 4),
        3 | 4 => Err("protobuf groups are not supported by Memcached timestamp rules".to_string()),
        _ => Err("protobuf field uses an invalid wire type".to_string()),
    }
}

fn fixed_value(input: &[u8], len: usize) -> Result<(&[u8], usize), String> {
    if input.len() < len {
        return Err("protobuf fixed-width field is truncated".to_string());
    }
    Ok((&input[..len], len))
}

fn read_varint(input: &[u8]) -> Result<(u64, usize), String> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().take(10).enumerate() {
        if index == 9 && byte > 1 {
            return Err("protobuf varint overflows u64".to_string());
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err("protobuf varint is truncated or too long".to_string())
}

fn validate_timestamp(
    field_number: u32,
    timestamp: u64,
    observed_at: DateTime<Utc>,
) -> Result<(), String> {
    u64::try_from(observed_at.timestamp()).map_err(|_| {
        format!("protobuf timestamp field {field_number} cannot use a pre-epoch observation")
    })?;
    // The captured field has second precision; preserve that observation precision.
    let observed_at = DateTime::from_timestamp(observed_at.timestamp(), 0)
        .expect("an existing timestamp remains representable without subsecond precision");
    crate::value_contract::time::validate_request_window(
        i128::from(timestamp) * crate::value_contract::time::NANOS_PER_SECOND,
        observed_at,
    )
    .map_err(|_| {
        format!("protobuf timestamp field {field_number} is outside the fixed ±5 second SET window")
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    const TIMESTAMP_FIELDS: &[u32] = &[50];

    fn message(timestamp: u64, stable: &[u8]) -> Vec<u8> {
        let mut value = vec![0x08, 0x07, 0x90, 0x03];
        encode_varint(timestamp, &mut value);
        value.extend_from_slice(&[0x12, stable.len() as u8]);
        value.extend_from_slice(stable);
        value
    }

    fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
        while value >= 0x80 {
            output.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    #[test]
    fn accepts_different_timestamps_inside_each_set_window() {
        let recorded_at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let actual_at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        assert!(
            matches_with_timestamp_fields(
                &message(1_699_999_995, b"stable"),
                &message(1_800_000_005, b"stable"),
                TIMESTAMP_FIELDS,
                recorded_at,
                actual_at,
            )
            .is_ok()
        );
    }

    #[test]
    fn second_precision_keeps_the_inclusive_boundary_for_subsecond_observations() {
        let observed_at = Utc.timestamp_opt(1_800_000_000, 999_999_999).unwrap();
        assert!(validate_timestamp(50, 1_799_999_995, observed_at).is_ok());
        assert!(validate_timestamp(50, 1_800_000_005, observed_at).is_ok());
        assert!(validate_timestamp(50, 1_799_999_994, observed_at).is_err());
        assert!(validate_timestamp(50, 1_800_000_006, observed_at).is_err());
        assert!(validate_timestamp(50, 0, Utc.timestamp_opt(-1, 0).unwrap()).is_err());
    }

    #[test]
    fn rejects_timestamp_outside_the_fixed_window() {
        let observed_at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let error = matches_with_timestamp_fields(
            &message(1_800_000_000, b"stable"),
            &message(1_799_999_994, b"stable"),
            TIMESTAMP_FIELDS,
            observed_at,
            observed_at,
        )
        .unwrap_err();
        assert!(error.contains("fixed ±5 second SET window"));
        assert!(!error.contains("1800000000"));
    }

    #[test]
    fn rejects_a_stable_field_difference() {
        let observed_at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let error = matches_with_timestamp_fields(
            &message(1_800_000_000, b"source"),
            &message(1_800_000_000, b"target"),
            TIMESTAMP_FIELDS,
            observed_at,
            observed_at,
        )
        .unwrap_err();
        assert!(error.contains("stable protobuf fields"));
    }

    #[test]
    fn rejects_missing_or_repeated_timestamp_fields() {
        let observed_at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let missing = [0x08, 0x07];
        assert!(
            matches_with_timestamp_fields(
                &missing,
                &missing,
                TIMESTAMP_FIELDS,
                observed_at,
                observed_at,
            )
            .unwrap_err()
            .contains("is missing")
        );

        let mut repeated = message(1_800_000_000, b"stable");
        repeated.extend_from_slice(&[0x90, 0x03]);
        encode_varint(1_800_000_000, &mut repeated);
        assert!(
            matches_with_timestamp_fields(
                &repeated,
                &repeated,
                TIMESTAMP_FIELDS,
                observed_at,
                observed_at,
            )
            .unwrap_err()
            .contains("more than once")
        );
    }
}
