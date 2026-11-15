//! Timestamp validation and relationships over independently observed clock facts.
use std::sync::Arc;

use anyhow::{Result, ensure};
use serde::Deserialize;
use traffic_policy::{
    AnalysisInput, ComparisonPolicy, Evaluation, EvaluationHost, EvidenceAccess, Finding,
    PolicyAction, PolicyDescriptor, PolicyProvider, ScopeKey, ValuePair,
};
use traffic_time::{
    ClockPair, TimeError, TimeMode,
    declaration::{
        TimeContract, TimeRelation, TimestampFormat, core_format, parse_time_pair, parse_time_value,
    },
};
use traffic_value::Value;

mod analysis;
mod observations;
use observations::TimestampObservations;

pub struct TimestampPolicy;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    config: TimeContract,
    #[serde(default = "super::observation_clock")]
    clock: String,
    #[serde(default)]
    accept_exact: bool,
}

impl PolicyProvider for TimestampPolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "time",
            version: 1,
            description: "Validate timestamp representations, observation deltas and clock relationships",
            actions: &[PolicyAction::Compare, PolicyAction::Analyze],
        }
    }

    fn prepare(&self, configuration: &Value) -> Result<Arc<dyn ComparisonPolicy>> {
        let configuration: Configuration =
            serde_json::from_value(serde_json::to_value(configuration)?)?;
        ensure!(
            !configuration.clock.is_empty()
                && configuration.clock.len() <= 128
                && configuration
                    .clock
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
            "timestamp requires a bounded observation clock identity"
        );
        let config = &configuration.config;
        ensure!(
            config.format != TimestampFormat::CalendarDate || config.utc_offset.is_some(),
            "calendar_date requires an explicit format utc_offset"
        );
        ensure!(
            config.utc_offset.is_none()
                || matches!(
                    config.format,
                    TimestampFormat::CalendarDate
                        | TimestampFormat::Iso8601Naive
                        | TimestampFormat::SqlDatetime
                ),
            "only calendar and naive time formats accept utc_offset"
        );
        ensure!(
            config
                .clock_group
                .as_ref()
                .is_none_or(|group| !group.is_empty() && group.len() <= 128),
            "timestamp clock_group requires 1..128 bytes"
        );
        config.offset()?;
        Ok(Arc::new(configuration))
    }

    fn analyze(&self, input: &AnalysisInput<'_>, _: &dyn EvidenceAccess) -> Result<Vec<Finding>> {
        analysis::analyze(input)
    }
}

impl ComparisonPolicy for Configuration {
    fn compatible(&self, other: &Value) -> Result<bool> {
        let other: Configuration = serde_json::from_value(serde_json::to_value(other)?)?;
        let mut left = self.config.clone();
        let mut right = other.config;
        left.clock_group = None;
        right.clock_group = None;
        Ok(self.clock == other.clock && left == right)
    }

    fn applies(&self, source: &Value, _: &Value) -> Result<bool> {
        Ok(parse_time_value(&serde_json::to_value(source)?, &self.config).is_ok())
    }

    fn evaluate(&self, pair: &ValuePair<'_>, host: &mut dyn EvaluationHost) -> Result<Evaluation> {
        if self.accept_exact && pair.source == pair.target {
            return Ok(Evaluation::matched());
        }
        let source = serde_json::to_value(pair.source)?;
        let target = serde_json::to_value(pair.target)?;
        let requirement = serde_json::from_value(serde_json::to_value(&self.config)?)?;
        let copied = self.config.relation == TimeRelation::PreserveOffset
            && host.permits_copy(&requirement)?;
        let facts = host.facts()?;
        let compared = if copied {
            parse_time_pair(&source, &target, &self.config)
        } else {
            self.compare(&source, &target, &facts)
        };
        let values = match compared {
            Ok(values) => values,
            Err(error) => {
                return Ok(Evaluation::mismatch(
                    pair,
                    "timestamp_relation",
                    &error.to_string(),
                ));
            }
        };
        if self.config.format != TimestampFormat::CalendarDate {
            let pattern = facts
                .pointer("/binding/pattern")
                .and_then(Value::as_str)
                .unwrap_or(pair.source_path);
            self.config.clock_scope.validate(pattern)?;
            let scope = if self.config.clock_scope.is_shared()
                && observations::is_implicit(self.config.clock_group.as_deref())
                && pattern.split('/').any(|part| part == "*")
            {
                ScopeKey::ArrayElement(pair.source_path.into())
            } else {
                host.scope(&self.config.clock_scope)?
            };
            host.observe(Box::new(TimestampObservations::one(
                self.clock.clone(),
                self.config.clock_group.clone(),
                scope,
                values,
            )))?;
        }
        Ok(Evaluation::matched().with_count("time_validations", 1))
    }
}

impl Configuration {
    fn compare(
        &self,
        source: &serde_json::Value,
        target: &serde_json::Value,
        facts: &Value,
    ) -> Result<(i128, i128), TimeError> {
        let pair = parse_time_pair(source, target, &self.config)?;
        let clocks = clock(facts, &self.clock)?;
        let mode = match self.config.relation {
            TimeRelation::RequestWindow => TimeMode::RequestWindow,
            TimeRelation::PreserveOffset => TimeMode::PreserveRelative,
        };
        if self.config.format == TimestampFormat::CalendarDate {
            return traffic_time::calendar::compare(
                source,
                target,
                self.config
                    .offset()
                    .map_err(|_| TimeError::InvalidValue)?
                    .ok_or(TimeError::InvalidValue)?,
                mode,
                clocks,
            );
        }
        let tolerance = traffic_time::timestamp_tolerance_nanos(clock(facts, "case")?, clocks);
        let clocks = traffic_time::timestamp_clocks(
            source,
            target,
            core_format(self.config.format)?,
            clocks,
        );
        traffic_time::compare_timestamp_nanos_with_tolerance(
            pair.0, pair.1, mode, clocks, tolerance,
        )?;
        Ok(pair)
    }
}

fn clock(facts: &Value, name: &str) -> Result<ClockPair, TimeError> {
    facts
        .pointer(&format!("/clocks/{}", traffic_value::path::escape(name)))
        .map(|value| serde_json::to_value(value).and_then(serde_json::from_value))
        .transpose()
        .map_err(|_| TimeError::InvalidValue)
        .map(Option::unwrap_or_default)
}
