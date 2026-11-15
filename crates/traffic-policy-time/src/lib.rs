//! Temporal comparisons over values and independently observed clocks.
use std::sync::Arc;

use anyhow::{Result, ensure};
use serde::Deserialize;
use traffic_policy::{
    ComparisonPolicy, Evaluation, EvaluationHost, PolicyAction, PolicyDescriptor, PolicyProvider,
    ValuePair,
};
use traffic_value::Value;

mod timestamp;
pub use timestamp::TimestampPolicy;

pub struct DurationPolicy;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    unit: Unit,
    #[serde(default = "observation_clock")]
    clock: String,
    #[serde(default)]
    accept_exact: bool,
}

fn observation_clock() -> String {
    "observation".into()
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Unit {
    Seconds,
    Milliseconds,
    Microseconds,
    Minutes,
    Hours,
}

impl Unit {
    fn native(self) -> traffic_time::DurationUnit {
        match self {
            Self::Seconds => traffic_time::DurationUnit::Seconds,
            Self::Milliseconds => traffic_time::DurationUnit::Milliseconds,
            Self::Microseconds => traffic_time::DurationUnit::Microseconds,
            Self::Minutes => traffic_time::DurationUnit::Minutes,
            Self::Hours => traffic_time::DurationUnit::Hours,
        }
    }
}

impl PolicyProvider for DurationPolicy {
    fn descriptor(&self) -> PolicyDescriptor {
        PolicyDescriptor {
            id: "duration",
            version: 1,
            description: "Compare duration deltas against independent observation clocks",
            actions: &[PolicyAction::Compare],
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
            "duration requires a bounded observation clock identity"
        );
        Ok(Arc::new(configuration))
    }
}

impl ComparisonPolicy for Configuration {
    fn validate_schema(&self, schema: &traffic_value::codec::FieldSchema) -> Result<()> {
        use traffic_value::codec::{FieldSchema, ValueType};
        ensure!(
            matches!(
                schema,
                FieldSchema::Dynamic | FieldSchema::Scalar | FieldSchema::Typed(ValueType::Number)
            ),
            "duration requires a numeric scalar field"
        );
        Ok(())
    }

    fn applies(&self, source: &Value, _: &Value) -> Result<bool> {
        Ok(
            traffic_time::parse_duration(&serde_json::to_value(source)?, self.unit.native())
                .is_ok(),
        )
    }

    fn evaluate(&self, pair: &ValuePair<'_>, host: &mut dyn EvaluationHost) -> Result<Evaluation> {
        if self.accept_exact && pair.source == pair.target {
            return Ok(Evaluation::matched());
        }
        let source = serde_json::to_value(pair.source)?;
        let target = serde_json::to_value(pair.target)?;
        let facts = host.facts()?;
        let clock = facts
            .pointer(&format!(
                "/clocks/{}",
                traffic_value::path::escape(&self.clock)
            ))
            .map(|value| serde_json::from_value(serde_json::to_value(value)?))
            .transpose()?
            .unwrap_or_default();
        let compared = compare(&source, &target, self.unit.native(), clock);
        Ok(match compared {
            Ok(()) => Evaluation::matched(),
            Err(error) => Evaluation::mismatch(pair, "duration_relation", &error.to_string()),
        })
    }
}

fn compare(
    source: &serde_json::Value,
    target: &serde_json::Value,
    unit: traffic_time::DurationUnit,
    clocks: traffic_time::ClockPair,
) -> Result<(), traffic_time::TimeError> {
    traffic_time::validate_numeric_category(source, target)?;
    let source = traffic_time::parse_duration(source, unit)?;
    let target = traffic_time::parse_duration(target, unit)?;
    traffic_time::compare_duration_nanos(source, target, clocks)
}
