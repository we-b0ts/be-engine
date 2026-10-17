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
            Some("relative_time" | "request_time" | "anchor" | "utc_offset" | "clock_group")
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
    map.entry("anchor".into())
        .or_insert_with(|| "case.request_start".into());
    if tagged {
        map.insert("kind".into(), "time".into());
    }
    Ok(())
}
