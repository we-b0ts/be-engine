//! Adapt response time policy and diagnostics to the shared pure time contracts.
#[cfg(test)]
use chrono::DateTime;
use serde_json::Value;

use super::model::ResponseDifferenceKind;
use traffic_contract::time::{self, DurationUnit, TimeError, TimeMode, TimestampFormat};
use traffic_policy_schema::response::{
    ResponseDurationUnit, ResponseTimeRule, ResponseTimestampFormat, ResponseTimestampMode,
};

pub use traffic_contract::time::ClockPair as RequestTimes;

/// Legacy declarations use the same installed policies as ordinary field rules.
pub fn compare(
    policies: &traffic_policy::PolicyRegistry,
    rule: ResponseTimeRule,
    source: &Value,
    target: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    use traffic_contract::{
        compare::{AnchorClocks, Field, RegisteredRules},
        rule::{self, FieldContract},
    };
    validate_inputs(source, target, times)?;
    let contract = match rule {
        ResponseTimeRule::Timestamp { format, mode } => FieldContract::Time {
            format: match format {
                ResponseTimestampFormat::UnixSeconds => rule::TimestampFormat::UnixSeconds,
                ResponseTimestampFormat::UnixMilliseconds => {
                    rule::TimestampFormat::UnixMilliseconds
                }
                ResponseTimestampFormat::Rfc3339 => rule::TimestampFormat::Rfc3339,
                ResponseTimestampFormat::AmzDate => rule::TimestampFormat::AmzDate,
            },
            relation: match mode {
                ResponseTimestampMode::RequestWindow => rule::TimeRelation::RequestWindow,
                ResponseTimestampMode::PreserveRelative => rule::TimeRelation::PreserveOffset,
            },
            anchor: rule::TimeAnchor::Observation,
            utc_offset: None,
            clock_group: None,
            clock_scope: rule::ClockScope::Shared,
        },
        ResponseTimeRule::Duration { unit } => FieldContract::Duration {
            unit: match unit {
                ResponseDurationUnit::Seconds => rule::DurationUnit::Seconds,
                ResponseDurationUnit::Milliseconds => rule::DurationUnit::Milliseconds,
                ResponseDurationUnit::Minutes => rule::DurationUnit::Minutes,
                ResponseDurationUnit::Hours => rule::DurationUnit::Hours,
            },
            anchor: rule::TimeAnchor::Observation,
        },
    };
    let mut definition = contract
        .registered_definition(false)
        .expect("temporal declarations provide a registered policy");
    if matches!(rule, ResponseTimeRule::Timestamp { .. }) {
        definition.options["tolerance"] = "fixed".into();
    }
    let contract = FieldContract::Policy(definition);
    let fields = [Field {
        rule_id: "content-time",
        pointer: "",
        contract: &contract,
    }];
    let compared = traffic_contract::compare::compare_all(
        source,
        target,
        &fields,
        &[],
        &[],
        AnchorClocks::for_response(RequestTimes::default(), times),
        &[],
        &RegisteredRules(policies),
    );
    if compared.passed() {
        return Ok(());
    }
    // Preserve established diagnostic categories after the policy rejects a value.
    match compare_original(rule, source, target, times) {
        Err(kind) => Err(kind),
        Ok(()) => Err(ResponseDifferenceKind::TimeFieldInvalid),
    }
}

fn compare_original(
    rule: ResponseTimeRule,
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    validate_inputs(expected, actual, times)?;
    if let ResponseTimeRule::Timestamp { format, .. } = rule {
        time::validate_representation(expected, actual, timestamp_format(format))
            .map_err(difference)?;
    }
    match rule {
        ResponseTimeRule::Timestamp { format, mode } => time::compare_timestamp_nanos(
            timestamp_nanos(expected, format)?,
            timestamp_nanos(actual, format)?,
            match mode {
                ResponseTimestampMode::RequestWindow => TimeMode::RequestWindow,
                ResponseTimestampMode::PreserveRelative => TimeMode::PreserveRelative,
            },
            time::timestamp_clocks(expected, actual, timestamp_format(format), times),
        ),
        ResponseTimeRule::Duration { unit } => time::compare_duration_nanos(
            numeric_nanos(expected, unit).ok_or(ResponseDifferenceKind::TimeFieldInvalid)?,
            numeric_nanos(actual, unit).ok_or(ResponseDifferenceKind::TimeFieldInvalid)?,
            times,
        ),
    }
    .map_err(difference)
}

pub fn compare_preserved_timestamp(
    policies: &traffic_policy::PolicyRegistry,
    format: ResponseTimestampFormat,
    source: &Value,
    target: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    compare(
        policies,
        ResponseTimeRule::Timestamp {
            format,
            mode: ResponseTimestampMode::PreserveRelative,
        },
        source,
        target,
        times,
    )
}

fn validate_inputs(
    expected: &Value,
    actual: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    if !(expected.is_number() && actual.is_number() || expected.is_string() && actual.is_string()) {
        return Err(ResponseDifferenceKind::TimeFieldInvalid);
    }
    times.require().map(|_| ()).map_err(difference)
}

fn difference(error: TimeError) -> ResponseDifferenceKind {
    match error {
        TimeError::ReferenceMissing => ResponseDifferenceKind::TimeReferenceMissing,
        TimeError::OutsideWindow => ResponseDifferenceKind::TimestampOutsideRequestWindow,
        TimeError::DeltaMismatch => ResponseDifferenceKind::DurationDeltaMismatch,
        _ => ResponseDifferenceKind::TimeFieldInvalid,
    }
}

fn timestamp_nanos(
    value: &Value,
    format: ResponseTimestampFormat,
) -> Result<i128, ResponseDifferenceKind> {
    time::parse_timestamp(value, timestamp_format(format), None).map_err(difference)
}

fn timestamp_format(format: ResponseTimestampFormat) -> TimestampFormat {
    match format {
        ResponseTimestampFormat::UnixSeconds => TimestampFormat::UnixSeconds,
        ResponseTimestampFormat::UnixMilliseconds => TimestampFormat::UnixMilliseconds,
        ResponseTimestampFormat::Rfc3339 => TimestampFormat::Rfc3339,
        ResponseTimestampFormat::AmzDate => TimestampFormat::AmzDate,
    }
}

fn numeric_nanos(value: &Value, unit: ResponseDurationUnit) -> Option<i128> {
    let unit = match unit {
        ResponseDurationUnit::Seconds => DurationUnit::Seconds,
        ResponseDurationUnit::Milliseconds => DurationUnit::Milliseconds,
        ResponseDurationUnit::Minutes => DurationUnit::Minutes,
        ResponseDurationUnit::Hours => DurationUnit::Hours,
    };
    time::parse_duration(value, unit).ok()
}

#[cfg(test)]
mod tests;
