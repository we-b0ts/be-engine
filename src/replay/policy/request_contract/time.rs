//! Shared request timestamp parsing and independently captured clock validation.
use super::*;
use config::TimeField;

pub(super) fn number(value: &Value) -> Result<f64> {
    let value = value.as_f64().context("timestamp must be numeric")?;
    ensure!(
        value.is_finite() && (-62_135_596_800.0..=253_402_300_799.0).contains(&value),
        "timestamp must be finite Unix seconds within years 1..9999"
    );
    Ok(value)
}
fn relative(
    source: f64,
    actual: f64,
    anchor: crate::replay::assertion::RequestTimes,
    tolerance: f64,
) -> Result<()> {
    let recorded = anchor
        .source
        .context("request time rule requires recorded request timestamp")?;
    let replay = anchor
        .target
        .context("request time rule requires an active case")?;
    let seconds = |time: DateTime<Utc>| {
        time.timestamp() as f64 + f64::from(time.timestamp_subsec_nanos()) / 1e9
    };
    ensure!(
        ((actual - seconds(replay)) - (source - seconds(recorded))).abs() <= tolerance,
        "request timestamp differs from its recorded relative time"
    );
    Ok(())
}
pub(super) fn compare(
    source: &Value,
    actual: &Value,
    rule: &TimeField,
    anchor: crate::replay::assertion::RequestTimes,
) -> Result<(f64, f64)> {
    ensure!(
        source.is_i64() == actual.is_i64() && source.is_u64() == actual.is_u64(),
        "timestamp numeric category changed"
    );
    let pair = (
        timestamp(source, rule.format)?,
        timestamp(actual, rule.format)?,
    );
    relative(pair.0, pair.1, anchor, config::tolerance(&rule.tolerance)?)?;
    Ok(pair)
}

pub(super) fn timestamp(value: &Value, format: config::RequestTimestampFormat) -> Result<f64> {
    if matches!(format, config::RequestTimestampFormat::Rfc3339) {
        let value = DateTime::parse_from_rfc3339(
            value
                .as_str()
                .context("timestamp must be an RFC3339 string")?,
        )?;
        return Ok(value.timestamp() as f64 + f64::from(value.timestamp_subsec_nanos()) / 1e9);
    }
    let unit = match format {
        config::RequestTimestampFormat::UnixSeconds => 1.0,
        config::RequestTimestampFormat::UnixMilliseconds => 1000.0,
        config::RequestTimestampFormat::Rfc3339 => unreachable!("handled string timestamp"),
    };
    number(&Value::from(
        value.as_f64().context("timestamp must be numeric")? / unit,
    ))
}
