//! Explicit time translation within a derived logical value.
use std::{borrow::Cow, collections::BTreeMap};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

mod selector;
pub use selector::{CompiledSelector, select, visit_uncompiled};

use crate::{
    compare::{self, AnchorClocks, Field, RuleMetadata},
    rule::{FieldContract, TimeAnchor, TimeContract, TimestampFormat},
    time,
};

pub struct TimeField<'a> {
    pub rule_id: &'a str,
    pub pointer: &'a str,
    pub contract: &'a TimeContract,
}

pub fn materialize(
    source: &Value,
    fields: &[TimeField<'_>],
    clocks: AnchorClocks,
    metadata: &dyn RuleMetadata,
) -> Result<Value> {
    Ok(materialize_cow(source, fields, clocks, metadata)?.into_owned())
}

pub fn materialize_cow<'a>(
    source: &'a Value,
    fields: &[TimeField<'_>],
    clocks: AnchorClocks,
    metadata: &dyn RuleMetadata,
) -> Result<Cow<'a, Value>> {
    let mut result = Cow::Borrowed(source);
    // A field declaration applies only to leaves present in this Source value.
    // Resolve them before requiring clocks or choosing shared clock precision.
    let mut selected = Vec::new();
    for field in fields {
        let pointers = select(field.pointer, source)?;
        if !pointers.is_empty() {
            selected.push((field.contract, pointers));
        }
    }
    let mut deltas = BTreeMap::new();
    for (contract, pointers) in &selected {
        if contract.format == TimestampFormat::CalendarDate {
            continue;
        }
        let pair = anchor(clocks, contract.anchor);
        let (source_clock, target_clock) = pair.require()?;
        let delta = time::date_nanos(target_clock) - time::date_nanos(source_clock);
        let quantum = pointers
            .iter()
            .filter_map(|pointer| source.pointer(pointer))
            .map(|value| value_quantum(value, contract.format))
            .max()
            .unwrap_or_else(|| quantum(contract.format));
        let entry = deltas.entry(contract.anchor).or_insert((delta, quantum));
        entry.1 = entry.1.max(quantum);
    }
    for (contract, pointers) in selected {
        for pointer in pointers {
            let value = result
                .to_mut()
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
    // Only writable fields are translated. Ordinary comparison contracts must
    // not accidentally reorder arrays or replace values in a delivery copy.
    let owned = fields
        .iter()
        .map(|field| {
            let time = field.contract;
            (
                field.rule_id,
                field.pointer,
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
        .collect::<Vec<_>>();
    let fields = owned
        .iter()
        .map(|(rule_id, pointer, contract)| Field {
            rule_id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    let check = compare::compare_all(source, &result, &fields, &[], &[], clocks, &[], metadata);
    ensure!(
        check.passed(),
        "derived response violates its time contracts: {:?}",
        check.differences
    );
    Ok(result)
}

fn anchor(clocks: AnchorClocks, anchor: TimeAnchor) -> time::ClockPair {
    clocks.get(anchor)
}

fn quantum(format: TimestampFormat) -> i128 {
    match format {
        TimestampFormat::UnixSeconds | TimestampFormat::AmzDate => 1_000_000_000,
        TimestampFormat::UnixMilliseconds => 1_000_000,
        TimestampFormat::UnixMicroseconds => 1000,
        _ => 1,
    }
}

pub fn shift(value: &Value, config: &TimeContract, delta: i128) -> Result<Value> {
    let unit = value_quantum(value, config.format);
    let delta = delta / unit * unit;
    let nanos = time::parse_timestamp(
        value,
        compare::core_format(config.format)?,
        config.offset()?,
    )?
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
                    let local = translated.with_timezone(&offset);
                    let mut rendered = local.format("%Y-%m-%dT%H:%M:%S").to_string();
                    if original.as_bytes().get(10) == Some(&b't') {
                        rendered.replace_range(10..11, "t");
                    }
                    append_fraction(
                        &mut rendered,
                        local.timestamp_subsec_nanos(),
                        fraction_width(original),
                    );
                    let suffix = if original.ends_with(['Z', 'z']) {
                        &original[original.len() - 1..]
                    } else {
                        &original[original.len() - 6..]
                    };
                    rendered.push_str(suffix);
                    rendered
                }
                TimestampFormat::AmzDate => translated.format("%Y%m%dT%H%M%SZ").to_string(),
                TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime => {
                    let local = translated.with_timezone(
                        &config
                            .offset()?
                            .context("naive timestamp requires offset")?,
                    );
                    let mut rendered = local
                        .format(if format == TimestampFormat::SqlDatetime {
                            "%Y-%m-%d %H:%M:%S%.f"
                        } else {
                            "%Y-%m-%dT%H:%M:%S%.f"
                        })
                        .to_string();
                    rendered.truncate(19);
                    append_fraction(
                        &mut rendered,
                        local.timestamp_subsec_nanos(),
                        fraction_width(original),
                    );
                    rendered
                }
                _ => unreachable!(),
            };
            Ok(text.into())
        }
    }
}

/// Source fixes textual precision independently for each physical value.
pub fn value_quantum(value: &Value, format: TimestampFormat) -> i128 {
    if matches!(
        format,
        TimestampFormat::Rfc3339 | TimestampFormat::Iso8601Naive | TimestampFormat::SqlDatetime
    ) && let Some(source) = value.as_str()
    {
        return 10_i128.pow(9 - fraction_width(source) as u32);
    }
    quantum(format)
}

fn fraction_width(text: &str) -> usize {
    if text.as_bytes().get(19) != Some(&b'.') {
        return 0;
    }
    text.as_bytes()[20..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count()
        .min(9)
}

fn append_fraction(output: &mut String, nanos: u32, width: usize) {
    if width != 0 {
        output.push('.');
        use std::fmt::Write as _;
        write!(output, "{:0width$}", nanos / 10_u32.pow(9 - width as u32))
            .expect("writing a String is infallible");
    }
}

#[cfg(test)]
mod tests {
    use super::select;
    use serde_json::json;

    #[test]
    fn exact_selectors_match_json_pointer_keys_and_canonical_array_indices() {
        let value = json!({
            "": {"a~/中": [7], "~1": null},
            "object": {"01": 1, "+1": 2, "x*y": 3}
        });
        for pointer in [
            "",
            "/",
            "//a~0~1中/0",
            "//~01",
            "/object/01",
            "/object/+1",
            "/object/x*y",
        ] {
            assert!(value.pointer(pointer).is_some(), "{pointer}");
            assert_eq!(select(pointer, &value).unwrap(), [pointer]);
        }
        for pointer in [
            "//a~0~1中/01",
            "//a~0~1中/+0",
            "//a~0~1中/-0",
            "//a~0~1中/1",
            "//a~0~1中/~1",
            "//a~0~1中/",
        ] {
            assert!(value.pointer(pointer).is_none(), "{pointer}");
            assert!(select(pointer, &value).unwrap().is_empty(), "{pointer}");
        }
    }

    #[test]
    fn wildcard_selectors_expand_only_array_indices_and_validate_the_entire_pattern() {
        let value = json!({
            "a/b": [[{"~": 1}, {}], [{"~": 2}, {"~": 3}], {"*": {"~": 4}}]
        });
        assert_eq!(
            select("/a~1b/*/*/~0", &value).unwrap(),
            ["/a~1b/0/0/~0", "/a~1b/1/0/~0", "/a~1b/1/1/~0"]
        );
        assert!(select("/a~1b/2/*/~0", &value).unwrap().is_empty());
        for pointer in ["a/b", "/missing/~2", "/missing/~", "/a\nb"] {
            assert!(select(pointer, &value).is_err(), "{pointer}");
        }
    }
}
