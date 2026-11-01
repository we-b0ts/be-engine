//! Parameter-aware date comparison; recorded headers and target output stay intact.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::replay::assertion::time::RequestTimes;
use crate::replay::policy::response_headers::ResponseHeaderDateRule;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResponseHeaderDateCandidate {
    pub header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    pub format: String,
}

pub(in crate::replay) fn compare(
    expected: &[String],
    actual: &[String],
    rules: &[ResponseHeaderDateRule],
    times: RequestTimes,
) -> Result<bool> {
    ensure!(
        expected.len() == 1 && actual.len() == 1,
        "header date rules require one complete header value on each side"
    );
    let mut source = parameters(&expected[0])?;
    let mut target = parameters(&actual[0])?;
    ensure!(
        source.keys().eq(target.keys()),
        "response header parameters differ"
    );
    for rule in rules {
        let selected = selected_keys(&source, rule.parameter.as_deref())?;
        let mut selected_day_delta = None;
        for key in selected {
            let source_value = source.get_mut(&key).expect("selected source parameter");
            let target_value = target.get_mut(&key).expect("equal parameter sets");
            let (source_stable, source_date, source_offset) =
                split_date(source_value, &rule.format)?;
            let (target_stable, target_date, target_offset) =
                split_date(target_value, &rule.format)?;
            ensure!(
                source_stable == target_stable && source_offset == target_offset,
                "stable response header text differs"
            );
            crate::value_contract::time::compare_calendar_dates(source_date, target_date, times)
                .context(
                    "response header date does not preserve the observation clock delta at day precision",
                )?;
            let day_delta = target_date.signed_duration_since(source_date).num_days();
            if let Some(previous) = selected_day_delta {
                ensure!(
                    previous == day_delta,
                    "related header dates changed inconsistently"
                );
            }
            selected_day_delta = Some(day_delta);
            *source_value = source_stable;
            *target_value = target_stable;
        }
    }
    Ok(source == target)
}

fn selected_keys(
    values: &BTreeMap<String, String>,
    parameter: Option<&str>,
) -> Result<Vec<String>> {
    match parameter {
        None => {
            ensure!(
                values.len() == 1,
                "whole-header date rules require a scalar header"
            );
            Ok(vec!["$".into()])
        }
        Some(name) => {
            let name = name.to_ascii_lowercase();
            let keys = values
                .keys()
                .filter(|key| **key == name || name == "filename" && key.as_str() == "filename*")
                .cloned()
                .collect::<Vec<_>>();
            ensure!(!keys.is_empty(), "response header date parameter is absent");
            Ok(keys)
        }
    }
}

fn split_date(value: &str, format: &str) -> Result<(String, NaiveDate, usize)> {
    let width = if format == "%Y%m%d" { 8 } else { 10 };
    let candidates = (0..=value.len().saturating_sub(width))
        .filter_map(|start| {
            let text = value.get(start..start + width)?;
            let date = NaiveDate::parse_from_str(text, format).ok()?;
            (date.format(format).to_string() == text).then_some((start, date))
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "response header must contain exactly one unambiguous calendar date"
    );
    let (start, date) = candidates[0];
    Ok((
        format!("{}{{date}}{}", &value[..start], &value[start + width..]),
        date,
        start,
    ))
}

fn parameters(value: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        value.len() <= 16 * 1024,
        "response header date value is oversized"
    );
    let parts = super::split_quoted(value, ';');
    let mut values = BTreeMap::from([(
        "$".into(),
        parts
            .first()
            .context("empty response header")?
            .trim()
            .to_ascii_lowercase(),
    )]);
    for part in parts.iter().skip(1) {
        let (name, value) = part
            .split_once('=')
            .context("invalid response header parameter")?;
        let name = name.trim().to_ascii_lowercase();
        let value = super::unquote(value.trim());
        let value = if name.ends_with('*') {
            let (charset, remainder) = value
                .split_once('\'')
                .context("extended header value lacks charset")?;
            let (language, _) = remainder
                .split_once('\'')
                .context("extended header value lacks language")?;
            values.insert(
                format!("$extended/{name}"),
                format!("{}'{language}", charset.to_ascii_lowercase()),
            );
            decode_extended(&value)?
        } else {
            value
        };
        ensure!(
            values.insert(name, value).is_none(),
            "duplicate response header parameter"
        );
    }
    // Scalar values are case-sensitive; only a disposition type is case-insensitive.
    if parts.len() == 1 {
        values.insert("$".into(), value.trim().to_owned());
    }
    Ok(values)
}

fn decode_extended(value: &str) -> Result<String> {
    let mut pieces = value.splitn(3, '\'');
    ensure!(
        pieces
            .next()
            .is_some_and(|charset| charset.eq_ignore_ascii_case("utf-8")),
        "extended header date values require UTF-8"
    );
    pieces
        .next()
        .context("extended header value lacks language")?;
    let text = pieces
        .next()
        .context("extended header value lacks content")?;
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < text.len() {
        if text.as_bytes()[index] == b'%' {
            let encoded = text
                .get(index + 1..index + 3)
                .context("incomplete header percent escape")?;
            decoded.push(u8::from_str_radix(encoded, 16).context("invalid header percent escape")?);
            index += 3;
        } else {
            decoded.push(text.as_bytes()[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).context("extended header filename is not UTF-8")
}

pub(super) fn candidates(
    header: &str,
    source: &[String],
    target: &[String],
) -> Vec<ResponseHeaderDateCandidate> {
    let (Some(source), Some(target)) = (
        source.first().filter(|_| source.len() == 1),
        target.first().filter(|_| target.len() == 1),
    ) else {
        return vec![];
    };
    let (Ok(source), Ok(target)) = (parameters(source), parameters(target)) else {
        return vec![];
    };
    if !source.keys().eq(target.keys()) {
        return vec![];
    }
    let mut candidates = Vec::new();
    for (parameter, source_value) in &source {
        let target_value = &target[parameter];
        if source_value == target_value {
            continue;
        }
        for format in ["%Y-%m-%d", "%Y%m%d", "%Y/%m/%d"] {
            if let (Ok((left, source_date, source_offset)), Ok((right, target_date, target_offset))) = (
                split_date(source_value, format),
                split_date(target_value, format),
            ) && left == right
                && source_offset == target_offset
                && source_date != target_date
            {
                candidates.push(ResponseHeaderDateCandidate {
                    header: header.into(),
                    parameter: (parameter != "$").then(|| parameter.trim_end_matches('*').into()),
                    format: format.into(),
                });
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

#[cfg(test)]
mod tests;
