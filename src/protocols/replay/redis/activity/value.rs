//! JSON refreshes reuse the shared timestamp kernel and keep all other leaves exact.
use super::*;
use crate::value_contract::{
    json::{parse_time_pair, parse_time_value},
    time,
};

pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() <= MAX_BYTES,
        "activity value exceeds its byte bound"
    );
    let value = crate::json_value::parse(bytes).context("activity value is not complete JSON")?;
    ensure!(value.is_object(), "activity refresh requires a JSON object");
    Ok(value)
}

pub(super) fn selected(
    state: &RedisReplayState,
    value: &Value,
    pointers: &[String],
    clock: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<(String, TimeContract)>> {
    let plan = state
        .request_contracts
        .compiled_rules()
        .and_then(|p| p.global_json.as_ref())
        .context("activity refresh requires its global JSON timestamp declarations")?;
    let contracts = plan.fields_with_clocks(
        value,
        crate::value_contract::json::AnchorClocks {
            dependency: time::ClockPair {
                source: Some(clock),
                target: Some(clock),
            },
            ..Default::default()
        },
    )?;
    pointers
        .iter()
        .map(|pointer| {
            let contract = contracts
                .iter()
                .find(|(path, _)| path == pointer)
                .and_then(|(_, c)| c.time())
                .context("activity refresh field has no recognized Source timestamp format")?;
            let leaf = value
                .pointer(pointer)
                .context("activity timestamp field is absent")?;
            time::validate_request_window(parse_time_value(leaf, &contract)?, clock)?;
            Ok((pointer.clone(), contract))
        })
        .collect()
}

pub(super) fn stable(value: &Value, fields: &[(String, TimeContract)]) -> Result<Value> {
    let mut value = value.clone();
    for (pointer, _) in fields {
        *value
            .pointer_mut(pointer)
            .context("activity timestamp field is absent")? = Value::Null;
    }
    Ok(value)
}

pub(super) fn check(
    source: &Value,
    actual: &Value,
    fields: &[(String, TimeContract)],
    source_clock: chrono::DateTime<chrono::Utc>,
    actual_clock: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    ensure!(
        stable(source, fields)? == stable(actual, fields)?,
        "activity refresh changed an unselected field, type or field set"
    );
    for (pointer, contract) in fields {
        let before = source
            .pointer(pointer)
            .context("activity Source timestamp absent")?;
        let after = actual
            .pointer(pointer)
            .context("activity Target timestamp absent")?;
        let (a, b) = parse_time_pair(before, after, contract)?;
        time::validate_request_window(a, source_clock)?;
        time::validate_request_window(b, actual_clock)?;
        time::compare_timestamp_nanos(
            a,
            b,
            time::TimeMode::PreserveRelative,
            time::ClockPair {
                source: Some(source_clock),
                target: Some(actual_clock),
            },
        )?;
    }
    Ok(())
}

pub(super) use traffic_protocol_redis::storage::activity::bulk;

pub(super) struct SourceValues<'a> {
    pub state: &'a RedisReplayState,
    pub pointers: &'a [String],
}

impl traffic_protocol_redis::storage::activity::ValueModel for SourceValues<'_> {
    type Value = Value;
    type Fields = Vec<(String, TimeContract)>;

    fn decode(&self, bytes: &[u8]) -> Result<Value> {
        decode(bytes)
    }

    fn fields(&self, value: &Value, clock: chrono::DateTime<chrono::Utc>) -> Result<Self::Fields> {
        selected(self.state, value, self.pointers, clock)
    }

    fn same_stable(&self, before: &Value, after: &Value, fields: &Self::Fields) -> Result<bool> {
        Ok(stable(before, fields)? == stable(after, fields)?)
    }
}
