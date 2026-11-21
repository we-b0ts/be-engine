//! Protocol-declared absolute expirations preserve their remaining lifetime.
use anyhow::{Result, ensure};

/// Return a comparison copy with only an independently verified absolute
/// deadline normalized. Keys, payloads and every other option stay untouched.
pub fn normalize(
    command: &str,
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    tolerance: std::time::Duration,
    clocks: impl FnOnce(i128) -> Result<(i64, i64)>,
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
    let (source_clock, target_clock) = clocks(scale)?;
    let source_remaining = source_deadline - i128::from(source_clock);
    let target_remaining = target_deadline - i128::from(target_clock);
    ensure!(
        (source_remaining > 0) == (target_remaining > 0)
            && source_remaining.abs_diff(target_remaining)
                <= u128::from(tolerance.as_secs()) * scale as u128,
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
