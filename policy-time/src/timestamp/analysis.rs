//! Source-proven temporal drafts are produced by the registered temporal owner.
use super::*;

pub(super) fn analyze(input: &AnalysisInput<'_>) -> Result<Vec<Finding>> {
    let Some(pair) = &input.values else {
        return Ok(Vec::new());
    };
    if pair.source == pair.target {
        return Ok(Vec::new());
    }
    let source = serde_json::to_value(pair.source)?;
    let target = serde_json::to_value(pair.target)?;
    let offset = input
        .facts
        .pointer("/settings/time/default_utc_offset")
        .and_then(Value::as_str)
        .unwrap_or("+08:00");
    if let Some(config) = traffic_time::declaration::recognize_timestamp(&source, offset) {
        let automatic = Configuration {
            config,
            clock: "observation".into(),
            accept_exact: true,
            tolerance: Tolerance::Observed,
        };
        if automatic.compare(&source, &target, input.facts).is_ok() {
            return Ok(Vec::new());
        }
    }
    let formats: &[TimestampFormat] = if source.is_number() && target.is_number() {
        match source.as_i64().unwrap_or(0) {
            946_684_800_000_000.. => &[TimestampFormat::UnixMicroseconds],
            946_684_800_000.. => &[TimestampFormat::UnixMilliseconds],
            946_684_800.. => &[TimestampFormat::UnixSeconds],
            _ => &[],
        }
    } else if source.is_string() && target.is_string() {
        &[
            TimestampFormat::Rfc3339,
            TimestampFormat::SqlDatetime,
            TimestampFormat::Iso8601Naive,
        ]
    } else {
        &[]
    };
    for format in formats {
        let configuration = Configuration {
            config: TimeContract {
                format: *format,
                relation: TimeRelation::PreserveOffset,
                anchor: Default::default(),
                utc_offset: None,
                clock_group: None,
                clock_scope: Default::default(),
            },
            clock: "observation".into(),
            accept_exact: false,
            tolerance: Tolerance::Observed,
        };
        if configuration.compare(&source, &target, input.facts).is_ok() {
            return Ok(vec![Finding {
                policy: "time".into(), source_path: pair.source_path.into(),
                summary: "Timestamp values preserve their independent observation-clock difference".into(),
                hint: "Trace Source generation and clock origin before declaring the timestamp format. Review its full evidence coverage and verify the applied rule through genuine Replay.".into(),
                proposal: Some(traffic_policy::Proposal::Field(serde_json::from_value(serde_json::json!({"kind":"time","formats":[format]}))?)),
                requirements: vec!["source_semantics".into(), "fresh_verification".into()],
            }]);
        }
    }
    Ok(Vec::new())
}
