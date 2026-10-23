//! Explicit translation of selected timestamps in a derived value. Originals
//! are never mutated, and decoding alone never grants permission to write.
use super::{
    json::{self, AnchorClocks, Field},
    time,
};
use crate::policy::{CompiledRule, FieldContract, TimeAnchor, TimeContract, TimestampFormat};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(test)]
mod tests;

pub(crate) fn materialize(
    source: &Value,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Value> {
    let mut result = source.clone();
    let mut deltas = BTreeMap::new();
    for rule in rules {
        for contract in rule.delivery_time.values() {
            if contract.format == TimestampFormat::CalendarDate {
                continue;
            }
            let pair = anchor(clocks, contract.anchor);
            let (source, target) = pair.require()?;
            let delta = time::date_nanos(target) - time::date_nanos(source);
            let quantum = quantum(contract.format);
            let entry = deltas.entry(contract.anchor).or_insert((delta, quantum));
            entry.1 = entry.1.max(quantum);
        }
    }
    for rule in rules {
        for (pointer, contract) in &rule.delivery_time {
            let pointers = select(pointer, source)?;
            ensure!(
                !pointers.is_empty(),
                "delivery timestamp {pointer:?} was not observed"
            );
            for pointer in pointers {
                let value = result
                    .pointer_mut(&pointer)
                    .context("delivery field disappeared")?;
                *value = if contract.format == TimestampFormat::CalendarDate {
                    time::calendar::rebase(
                        value,
                        contract
                            .offset()?
                            .context("calendar_date requires utc_offset")?,
                        anchor(clocks, contract.anchor),
                    )?
                } else {
                    let (delta, quantum) = deltas[&contract.anchor];
                    shift(value, contract, delta / quantum * quantum)?
                };
            }
        }
    }
    // Only writable fields are translated. Ordinary comparison contracts must
    // not accidentally reorder arrays or replace values in a delivery copy.
    let owned = rules
        .iter()
        .flat_map(|rule| {
            rule.delivery_time.iter().map(move |(pointer, time)| {
                (
                    rule.rule.id.clone(),
                    pointer.clone(),
                    FieldContract::Time {
                        format: time.format,
                        relation: time.relation,
                        anchor: time.anchor,
                        utc_offset: time.utc_offset.clone(),
                        clock_group: time.clock_group.clone(),
                        clock_scope: time.clock_scope.clone(),
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    let fields = owned
        .iter()
        .map(|(rule_id, pointer, contract)| Field {
            rule_id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    let check = json::compare(source, &result, &fields, clocks);
    ensure!(
        check.passed(),
        "derived response violates its time contracts: {:?}",
        check.differences
    );
    Ok(result)
}

fn anchor(clocks: AnchorClocks, anchor: TimeAnchor) -> time::ClockPair {
    match anchor {
        TimeAnchor::DependencyRequestStart => clocks.dependency,
        TimeAnchor::ApiRequestStart | TimeAnchor::DependencyDelivery => time::ClockPair::default(),
    }
}

fn quantum(format: TimestampFormat) -> i128 {
    match format {
        TimestampFormat::UnixSeconds | TimestampFormat::AmzDate => 1_000_000_000,
        TimestampFormat::UnixMilliseconds => 1_000_000,
        TimestampFormat::UnixMicroseconds => 1000,
        _ => 1,
    }
}

pub(crate) fn shift(value: &Value, config: &TimeContract, delta: i128) -> Result<Value> {
    let nanos = time::parse_timestamp(value, json::core_format(config.format)?, config.offset()?)?
        .checked_add(delta)
        .context("delivery time overflow")?;
    match config.format {
        TimestampFormat::UnixSeconds
        | TimestampFormat::UnixMilliseconds
        | TimestampFormat::UnixMicroseconds => {
            ensure!(
                value.is_number(),
                "numeric timestamp delivery requires a number"
            );
            let unit = quantum(config.format);
            if value.is_i64() {
                return Ok(i64::try_from(nanos / unit)
                    .context("signed timestamp overflow")?
                    .into());
            }
            if value.is_u64() {
                return Ok(u64::try_from(nanos / unit)
                    .context("unsigned timestamp overflow")?
                    .into());
            }
            let negative = nanos < 0;
            let whole = nanos.unsigned_abs() / unit as u128;
            let remainder = nanos.unsigned_abs() % unit as u128;
            let digits = match config.format {
                TimestampFormat::UnixSeconds => 9,
                TimestampFormat::UnixMilliseconds => 6,
                _ => 3,
            };
            let text = format!(
                "{}{whole}.{remainder:0digits$}",
                if negative { "-" } else { "" }
            );
            let number = text.parse::<serde_json::Number>()?;
            // Preserve fractional numeric representation even when remainder is 0.
            Ok(Value::Number(number))
        }
        format => {
            let seconds = i64::try_from(nanos.div_euclid(time::NANOS_PER_SECOND))?;
            let subsec = u32::try_from(nanos.rem_euclid(time::NANOS_PER_SECOND))?;
            let translated = Utc
                .timestamp_opt(seconds, subsec)
                .single()
                .context("timestamp outside calendar range")?;
            let original = value.as_str().context("text timestamp required")?;
            let text = match format {
                TimestampFormat::Rfc3339 => {
                    let offset = *DateTime::parse_from_rfc3339(original)?.offset();
                    translated
                        .with_timezone(&offset)
                        .to_rfc3339_opts(SecondsFormat::AutoSi, original.ends_with(['Z', 'z']))
                }
                TimestampFormat::AmzDate => translated.format("%Y%m%dT%H%M%SZ").to_string(),
                TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime => translated
                    .with_timezone(
                        &config
                            .offset()?
                            .context("naive timestamp requires offset")?,
                    )
                    .format(if format == TimestampFormat::SqlDatetime {
                        "%Y-%m-%d %H:%M:%S%.f"
                    } else {
                        "%Y-%m-%dT%H:%M:%S%.f"
                    })
                    .to_string(),
                _ => unreachable!(),
            };
            Ok(text.into())
        }
    }
}

pub(super) fn select(pattern: &str, value: &Value) -> Result<Vec<String>> {
    fn walk(parts: &[&str], value: &Value, path: String, out: &mut Vec<String>) {
        let Some((part, rest)) = parts.split_first() else {
            out.push(path);
            return;
        };
        if *part == "*" && value.is_array() {
            for (i, child) in value.as_array().unwrap().iter().enumerate() {
                walk(rest, child, format!("{path}/{i}"), out);
            }
        } else if let Some(child) = value.pointer(&format!("/{part}")) {
            walk(rest, child, format!("{path}/{part}"), out);
        }
    }
    crate::policy::validate_pointer(pattern, true)?;
    let mut out = Vec::new();
    walk(
        &pattern.split('/').skip(1).collect::<Vec<_>>(),
        value,
        String::new(),
        &mut out,
    );
    Ok(out)
}
