//! Reject numeric tokens that serde_json would silently round. Decimal spelling
//! may differ (1.10 == 11e-1), but distinct exact decimal values never collapse.
pub(super) fn preserves_decimal_tokens(bytes: &[u8]) -> bool {
    let mut index = 0;
    let mut string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit() || b"-+.eE".contains(&bytes[index]))
            {
                index += 1;
            }
            let Ok(token) = std::str::from_utf8(&bytes[start..index]) else {
                return false;
            };
            let Ok(number) = token.parse::<serde_json::Number>() else {
                return false;
            };
            let Some(expected) = decimal(token) else {
                return false;
            };
            if Some(expected) != decimal(&number.to_string()) {
                return false;
            }
            continue;
        }
        index += 1;
    }
    true
}

fn decimal(value: &str) -> Option<(bool, String, i64)> {
    let (mantissa, exponent) = value.split_once(['e', 'E']).unwrap_or((value, "0"));
    let mut power = exponent.parse::<i64>().ok()?;
    let negative = mantissa.starts_with('-');
    let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    power = power.checked_sub(i64::try_from(fraction.len()).ok()?)?;
    let mut digits = format!("{whole}{fraction}")
        .trim_start_matches('0')
        .to_string();
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    while digits.ends_with('0') {
        digits.pop();
        power = power.checked_add(1)?;
    }
    Some((negative, digits, power))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_integer_and_decimal_identity_survive_or_are_rejected() {
        for value in [
            "18446744073709551615",
            "9007199254740993",
            "1.10",
            "11e-1",
            "1e3",
            "-0.0",
            "1.2345678901234567",
        ] {
            assert!(preserves_decimal_tokens(value.as_bytes()), "{value}");
        }
        for value in [
            "18446744073709551616",
            "1.10000000000000001",
            "9007199254740993.0",
            "1e-400",
            "1e400",
        ] {
            assert!(!preserves_decimal_tokens(value.as_bytes()), "{value}");
            assert!(crate::json_value::parse(format!("{{\"id\":{value}}}").as_bytes()).is_none());
        }
        assert!(preserves_decimal_tokens(br#"{"text":"number 1.10000000000000001 and escaped \"18446744073709551616\"","n":1.1}"#));
    }
}
