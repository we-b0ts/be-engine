//! Named abbreviations preserve explicit units and typed comparison semantics.
use anyhow::{Context, Result, ensure};
use serde_yaml::{Mapping, Value};

pub(super) fn transform(value: &mut Value, tagged: bool, compact: bool) -> Result<()> {
    if value.as_str() == Some("unordered") && tagged {
        if !compact {
            *value = serde_yaml::from_str("{kind: unordered}")?;
        }
        return Ok(());
    }
    let Some(map) = value.as_mapping_mut() else {
        return Ok(());
    };
    ensure!(
        !map.contains_key("anchor"),
        "anchor is not configurable; time contracts use the corresponding dependency request start"
    );
    if !compact {
        ensure!(
            map.get("clock_group")
                .and_then(Value::as_str)
                .is_none_or(|group| !group.starts_with("schema.")),
            "schema. clock groups are reserved for implicit field clocks"
        );
    }
    if !compact && map.get("relation").and_then(Value::as_str) == Some("preserve_offset") {
        remove_relative_offset(map)?;
    }
    if compact {
        if tagged && map.len() == 1 && map.get("kind").and_then(Value::as_str) == Some("unordered")
        {
            *value = "unordered".into();
        } else if map.get("format").is_some()
            && (!tagged || map.get("kind").and_then(Value::as_str) == Some("time"))
        {
            let alias = match map.get("relation").and_then(Value::as_str) {
                Some("preserve_offset") => Some("relative_time"),
                Some("request_window") => Some("request_time"),
                _ => None,
            };
            if let Some(alias) = alias {
                let format = map.remove("format").expect("format checked");
                map.remove("relation");
                map.remove("kind");
                let mut result = Mapping::new();
                result.insert(alias.into(), format);
                result.extend(std::mem::take(map));
                *map = result;
            }
        }
        return Ok(());
    }
    let aliases = ["relative_time", "request_time"]
        .into_iter()
        .filter(|key| map.contains_key(*key))
        .collect::<Vec<_>>();
    if aliases.is_empty() {
        return Ok(());
    }
    ensure!(
        aliases.len() == 1,
        "one time abbreviation is permitted per contract"
    );
    let alias = aliases[0];
    ensure!(
        map.keys().all(|key| matches!(
            key.as_str(),
            Some("relative_time" | "request_time" | "utc_offset" | "clock_group" | "clock_scope")
        )),
        "time abbreviations cannot mix kind/format/relation or unknown fields"
    );
    let format = map.remove(alias).context("missing time format")?;
    ensure!(
        format.as_str().is_some_and(|s| !s.is_empty()),
        "time abbreviation requires an explicit format"
    );
    map.insert("format".into(), format);
    map.insert(
        "relation".into(),
        if alias == "relative_time" {
            "preserve_offset"
        } else {
            "request_window"
        }
        .into(),
    );
    if tagged {
        map.insert("kind".into(), "time".into());
    }
    if alias == "relative_time" {
        remove_relative_offset(map)?;
    }
    Ok(())
}

fn remove_relative_offset(map: &mut Mapping) -> Result<()> {
    let Some(offset) = map.get("utc_offset") else {
        return Ok(());
    };
    if map.get("format").and_then(Value::as_str) == Some("calendar_date") {
        return validate_legacy_offset(offset);
    }
    ensure!(
        matches!(
            map.get("format").and_then(Value::as_str),
            Some("iso8601_naive" | "sql_datetime")
        ),
        "utc_offset is only valid for a naive timestamp"
    );
    validate_legacy_offset(offset)?;
    map.remove("utc_offset");
    Ok(())
}

pub(super) fn validate_legacy_offset(offset: &Value) -> Result<()> {
    let offset = offset
        .as_str()
        .context("legacy UTC offset must be a string")?;
    crate::policy::TimeContract {
        format: crate::policy::TimestampFormat::SqlDatetime,
        relation: crate::policy::TimeRelation::PreserveOffset,
        anchor: crate::policy::TimeAnchor::Observation,
        utc_offset: Some(offset.into()),
        clock_group: None,
        clock_scope: Default::default(),
    }
    .offset()?;
    Ok(())
}
