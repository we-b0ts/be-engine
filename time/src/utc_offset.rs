//! Exact signed UTC offsets for temporal declarations.
use anyhow::{Context, Result, ensure};

pub fn parse_utc_offset(value: &str) -> Result<i32> {
    let bytes = value.as_bytes();
    ensure!(
        bytes.len() == 6 && matches!(bytes[0], b'+' | b'-') && bytes[3] == b':',
        "timezone must use +HH:MM or -HH:MM"
    );
    ensure!(
        [bytes[1], bytes[2], bytes[4], bytes[5]]
            .into_iter()
            .all(|byte| byte.is_ascii_digit()),
        "timezone must use numeric hours and minutes"
    );
    let hours = value[1..3]
        .parse::<i32>()
        .context("invalid timezone hour")?;
    let minutes = value[4..6]
        .parse::<i32>()
        .context("invalid timezone minute")?;
    ensure!(hours <= 23 && minutes <= 59, "timezone is out of range");
    let seconds = hours * 3_600 + minutes * 60;
    Ok(if bytes[0] == b'-' { -seconds } else { seconds })
}
