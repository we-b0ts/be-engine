//! Strict URL comparison copies with explicitly selected, unique query values.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub struct SelectedQuery {
    pub remainder: String,
    pub values: BTreeMap<String, Value>,
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "URL query names require bounded ASCII names"
    );
    Ok(())
}

/// Validate the selected UTC date against its own timestamp, retaining every
/// other decoded segment. The caller resolves the declared timestamp reference.
pub fn date_segment_remainder(
    value: &Value,
    separator: char,
    index: usize,
    anchor_nanos: i128,
) -> Result<String> {
    let date =
        chrono::DateTime::from_timestamp(i64::try_from(anchor_nanos.div_euclid(1_000_000_000))?, 0)
            .context("URL date anchor is outside its bounds")?
            .format("%Y%m%d")
            .to_string();
    let mut parts = value
        .as_str()
        .context("URL date scope is not a string")?
        .split(separator)
        .collect::<Vec<_>>();
    ensure!(
        parts.len() <= 64 && parts.get(index).is_some_and(|v| *v == date),
        "URL date segment differs from its own signing time"
    );
    parts[index] = "";
    Ok(parts.join(&separator.to_string()))
}

pub fn select(value: &Value, names: &BTreeSet<&str>) -> Result<SelectedQuery> {
    for name in names {
        validate_name(name)?;
    }
    let value = value.as_str().context("URL field must be a string")?;
    ensure!(
        value.len() <= 16_384 && !value.chars().any(char::is_control),
        "URL exceeds bounds"
    );
    let url = url::Url::parse(value).context("URL field requires an absolute URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "URL requires HTTP(S) and a host"
    );
    let (body, fragment) = value
        .split_once('#')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let (prefix, query) = body.split_once('?').context("URL query is absent")?;
    let mut values = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut remainder = Vec::new();
    for (index, raw) in query.split('&').enumerate() {
        ensure!(
            index < 64 && !raw.is_empty(),
            "URL query exceeds bounds or contains an empty member"
        );
        let pairs = url::form_urlencoded::parse(raw.as_bytes()).collect::<Vec<_>>();
        ensure!(pairs.len() == 1, "URL query member is invalid");
        let (name, decoded) = &pairs[0];
        ensure!(seen.insert(name.to_string()), "duplicate URL query name");
        if names.contains(name.as_ref()) {
            let (raw_name, _) = raw
                .split_once('=')
                .context("selected URL query value is absent")?;
            ensure!(
                raw_name == name,
                "selected URL query name must use its literal ASCII spelling"
            );
            values.insert(name.to_string(), Value::String(decoded.to_string()));
            remainder.push(format!("{raw_name}="));
        } else {
            remainder.push(raw.to_owned());
        }
    }
    ensure!(
        values.len() == names.len(),
        "selected URL query field is missing"
    );
    Ok(SelectedQuery {
        remainder: format!(
            "{prefix}?{}{}",
            remainder.join("&"),
            fragment.map_or(String::new(), |f| format!("#{f}"))
        ),
        values,
    })
}
