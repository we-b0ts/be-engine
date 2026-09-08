//! Explicit relative-time translation of matched Redis response copies.
mod config;
pub(crate) mod evidence;
use super::*;
use chrono::{DateTime, Utc};
pub use config::{
    RedisTimeShiftRead, RedisTimeShiftSelector, RedisTimestampFormat, RelativeTime,
    RelativeTimeField,
};
use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct ResponseShift {
    recorded_at: DateTime<Utc>,
    payload: Value,
    fields: BTreeMap<String, RelativeTimeField>,
    pub rule_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TimeShiftObservation {
    pub rule_id: String,
    pub case_id: Option<String>,
    pub connection_id: Uuid,
    pub sequence: u64,
    pub offset_milliseconds: i64,
}

impl ResponseShift {
    pub(super) fn prepare(
        record: &RecordedExchange,
        rules: &[(String, RedisTimeShiftRead)],
    ) -> Result<Self> {
        ensure!(
            record.replay_safe
                && !record.session_setup
                && !record.cache_snapshot_hit
                && record.cache_snapshot_rule.is_none()
                && record.global_dependency_reason.as_deref() != Some("background_rule")
                && record.outcome == DependencyExchangeOutcome::Response
                && record.response_kind == "bulk_string"
                && !record.response.truncated
                && record.args.iter().all(|a| !a.truncated),
            "Redis time-shift requires a complete successful ordinary JSON read"
        );
        let recorded_at = record
            .timestamp
            .context("Redis time-shift requires the original exchange timestamp")?;
        let payload = decode_payload(&record.response.decode()?)?;
        let mut fields = BTreeMap::new();
        let mut rule_ids = Vec::new();
        for (id, read) in rules {
            for (path, field) in &read.response_json {
                ensure!(
                    payload.pointer(path).and_then(Value::as_i64).is_some(),
                    "Redis time-shift selected field is missing or is not an integer timestamp"
                );
                ensure!(
                    fields.insert(path.clone(), *field).is_none(),
                    "overlapping Redis time-shift fields"
                );
            }
            rule_ids.push(id.clone());
        }
        Ok(Self {
            recorded_at,
            payload,
            fields,
            rule_ids,
        })
    }
    pub(super) fn render(&self, now: DateTime<Utc>) -> Result<(Vec<u8>, i64)> {
        let offset_ms = now
            .timestamp_millis()
            .checked_sub(self.recorded_at.timestamp_millis())
            .context("Redis time-shift offset overflow")?;
        let mut payload = self.payload.clone();
        for (path, field) in &self.fields {
            let offset = match field.format {
                RedisTimestampFormat::UnixMilliseconds => offset_ms,
                RedisTimestampFormat::UnixSeconds => now
                    .timestamp()
                    .checked_sub(self.recorded_at.timestamp())
                    .context("Redis time-shift seconds overflow")?,
            };
            let value = payload
                .pointer_mut(path)
                .context("Redis time-shift field disappeared")?;
            let shifted = value
                .as_i64()
                .context("Redis time-shift requires integer timestamps")?
                .checked_add(offset)
                .context("Redis time-shift timestamp overflow")?;
            *value = Value::from(shifted);
        }
        let body = serde_json::to_vec(&payload)?;
        let mut response = format!("${}\r\n", body.len()).into_bytes();
        response.extend(body);
        response.extend_from_slice(b"\r\n");
        Ok((response, offset_ms))
    }
}

pub(super) fn decode_payload(raw: &[u8]) -> Result<Value> {
    ensure!(
        raw.len() <= 1024 * 1024,
        "Redis time-shift response exceeds 1 MiB"
    );
    ensure!(
        raw.first() == Some(&b'$'),
        "Redis time-shift requires a RESP bulk string"
    );
    let end = raw
        .windows(2)
        .position(|s| s == b"\r\n")
        .context("invalid Redis bulk header")?;
    let len: usize = std::str::from_utf8(&raw[1..end])?
        .parse()
        .context("invalid Redis bulk length")?;
    let start = end + 2;
    let tail = start
        .checked_add(len)
        .context("Redis bulk length overflow")?;
    ensure!(
        tail.checked_add(2) == Some(raw.len()) && raw.get(tail..) == Some(b"\r\n"),
        "Redis time-shift requires one complete bulk response"
    );
    super::json::parse(&raw[start..tail])
        .context("Redis time-shift requires bounded JSON without duplicate members")
}

impl RedisReplayState {
    pub(in crate::replay) fn configure_time_shift(
        &mut self,
        rules: &[(String, RedisTimeShiftSelector)],
    ) -> Result<()> {
        for exchange in &mut self.exchanges {
            let selected = rules
                .iter()
                .filter(|(_, selector)| selector.matches(&exchange.record, &exchange.args))
                .map(|(id, selector)| (id.clone(), selector.read.clone()))
                .collect::<Vec<_>>();
            if !selected.is_empty() {
                ensure!(
                    !exchange.reusable_snapshot && !exchange.connection_independent,
                    "Redis time-shift cannot renew reusable/background snapshot responses"
                );
                exchange.response_time_shift =
                    Some(ResponseShift::prepare(&exchange.record, &selected)?);
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
