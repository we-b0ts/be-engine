//! Validate fixed offsets in historical timestamp declarations.
use super::*;
use chrono::FixedOffset;
use config::TimeField;

pub(super) fn offset(rule: &TimeField) -> Result<FixedOffset> {
    // Both values use the same origin, so its offset cancels in the difference.
    let offset = rule.utc_offset.as_deref().unwrap_or("+00:00");
    ensure!(
        offset != "-00:00"
            && offset.len() == 6
            && matches!(offset.as_bytes()[0], b'+' | b'-')
            && offset.as_bytes()[3] == b':'
            && offset
                .bytes()
                .enumerate()
                .all(|(i, b)| matches!(i, 0 | 3) || b.is_ascii_digit()),
        "utc_offset must use explicit +/-HH:MM"
    );
    let parsed = DateTime::parse_from_rfc3339(&format!("2000-01-01T00:00:00{offset}"))?;
    ensure!(
        parsed.offset().local_minus_utc().abs() <= 14 * 3600,
        "utc_offset exceeds 14 hours"
    );
    Ok(*parsed.offset())
}
