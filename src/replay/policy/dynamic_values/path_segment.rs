//! Explicit path-segment templates: fixed components, shaped nonces and local clocks.
use crate::replay::{
    assertion::time::{RequestTimes, compare},
    policy::{ResponseTimeRule, ResponseTimestampFormat},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSegmentCapture {
    pub index: usize,
    pub template: String,
    pub fields: BTreeMap<String, PathSegmentField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathSegmentField {
    Exact,
    Random {
        format: String,
        length: usize,
    },
    Timestamp {
        format: String,
        #[serde(default = "utc_timezone", skip_serializing_if = "is_utc_timezone")]
        timezone: String,
        #[serde(
            default,
            skip_serializing_if = "crate::policy::native::PathTimestampMode::is_request_window"
        )]
        mode: crate::policy::native::PathTimestampMode,
    },
}

fn utc_timezone() -> String {
    "UTC".into()
}
fn is_utc_timezone(value: &str) -> bool {
    value == "UTC"
}

enum Part<'a> {
    Literal(&'a str),
    Field(&'a str),
}

impl PathSegmentCapture {
    pub(super) fn validate(&self, path: &str) -> Result<()> {
        ensure!(
            self.index < 64
                && path
                    .strip_prefix('/')
                    .context("capture path must be absolute")?
                    .split('/')
                    .nth(self.index)
                    == Some("*"),
            "path_segment index must select a wildcard segment"
        );
        let parts = self.parts()?;
        let names: BTreeSet<_> = parts
            .iter()
            .filter_map(|part| match part {
                Part::Field(name) => Some(*name),
                _ => None,
            })
            .collect();
        ensure!(
            names.len() == self.fields.len()
                && self.fields.keys().all(|name| names.contains(name.as_str())),
            "path template fields must be declared exactly once"
        );
        ensure!(
            self.fields
                .values()
                .any(|field| !matches!(field, PathSegmentField::Exact)),
            "path capture requires a dynamic field"
        );
        for field in self.fields.values() {
            match field {
                PathSegmentField::Exact => (),
                PathSegmentField::Random { format, length } => ensure!(
                    format == "hex" && (1..=1024).contains(length),
                    "random path fields require format hex and length 1..1024"
                ),
                PathSegmentField::Timestamp {
                    format, timezone, ..
                } => ensure!(
                    format == "%Y%m%d%H%M%S" && timezone == "UTC",
                    "path timestamp requires format %Y%m%d%H%M%S and timezone UTC"
                ),
            }
        }
        Ok(())
    }

    fn parts(&self) -> Result<Vec<Part<'_>>> {
        ensure!(
            !self.template.is_empty() && self.template.len() <= 1024 && self.fields.len() <= 32,
            "path template exceeds bounds"
        );
        let mut remaining = self.template.as_str();
        let mut parts = Vec::new();
        let mut names = BTreeSet::new();
        while let Some(start) = remaining.find('{') {
            let literal = &remaining[..start];
            ensure!(
                !literal.contains('}') && (parts.is_empty() || !literal.is_empty()),
                "path fields require separating literals"
            );
            if !literal.is_empty() {
                parts.push(Part::Literal(literal));
            }
            remaining = &remaining[start + 1..];
            let end = remaining
                .find('}')
                .context("unclosed path template field")?;
            let name = &remaining[..end];
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    && names.insert(name),
                "invalid or repeated path field"
            );
            parts.push(Part::Field(name));
            remaining = &remaining[end + 1..];
        }
        ensure!(!remaining.contains('}'), "unmatched path template brace");
        if !remaining.is_empty() {
            parts.push(Part::Literal(remaining));
        }
        ensure!(!names.is_empty(), "path template requires fields");
        for part in &parts {
            if let Part::Literal(literal) = part {
                ensure!(
                    literal
                        .bytes()
                        .all(|byte| matches!(byte, b'_' | b'-' | b'.' | b':')),
                    "path template separators must use _, -, . or :"
                );
            }
        }
        Ok(parts)
    }

    pub(in crate::replay) fn extract(&self, uri: &str) -> Result<String> {
        extract(uri, self.index)
    }

    fn values<'a>(&self, value: &'a str) -> Result<BTreeMap<String, &'a str>> {
        let parts = self.parts()?;
        let mut remaining = value;
        let mut values = BTreeMap::new();
        for (index, part) in parts.iter().enumerate() {
            match part {
                Part::Literal(literal) => {
                    remaining = remaining
                        .strip_prefix(literal)
                        .context("path template literal differs")?
                }
                Part::Field(name) => {
                    let end = match parts.get(index + 1) {
                        Some(Part::Literal(literal)) => remaining
                            .find(literal)
                            .context("path template separator absent")?,
                        _ => remaining.len(),
                    };
                    let field = &remaining[..end];
                    ensure!(!field.is_empty(), "empty path field");
                    values.insert((*name).to_string(), field);
                    remaining = &remaining[end..];
                }
            }
        }
        ensure!(remaining.is_empty(), "path template has trailing bytes");
        Ok(values)
    }

    pub(in crate::replay) fn compare(
        &self,
        source: &str,
        target: &str,
        times: RequestTimes,
    ) -> Result<()> {
        let left = self.values(source)?;
        let right = self.values(target)?;
        for (name, field) in &self.fields {
            let a = left.get(name).context("source path field absent")?;
            let b = right.get(name).context("target path field absent")?;
            match field {
                PathSegmentField::Exact => ensure!(a == b, "fixed path field differs"),
                PathSegmentField::Random { length, .. } => ensure!(
                    [a, b].iter().all(|value| value.len() == *length
                        && value.bytes().all(|byte| byte.is_ascii_hexdigit())),
                    "random path field has invalid shape"
                ),
                PathSegmentField::Timestamp { format, mode, .. } => {
                    let parse = |text: &str| -> Result<DateTime<Utc>> {
                        ensure!(
                            text.len() == 14 && text.bytes().all(|byte| byte.is_ascii_digit()),
                            "invalid path timestamp"
                        );
                        let parsed = NaiveDateTime::parse_from_str(text, format)
                            .context("invalid path timestamp")?;
                        ensure!(
                            parsed.nanosecond() < 1_000_000_000,
                            "path timestamp cannot contain leap seconds"
                        );
                        ensure!(
                            parsed.format(format).to_string() == text,
                            "noncanonical path timestamp"
                        );
                        Ok(parsed.and_utc())
                    };
                    let (a, b) = (parse(a)?, parse(b)?);
                    if *mode == crate::policy::native::PathTimestampMode::PreserveOrRequestWindow
                        && source == target
                    {
                        continue;
                    }
                    compare(
                        ResponseTimeRule::Timestamp {
                            mode: Default::default(),
                            format: ResponseTimestampFormat::Rfc3339,
                        },
                        &serde_json::Value::String(a.to_rfc3339()),
                        &serde_json::Value::String(b.to_rfc3339()),
                        times,
                    )
                    .map_err(|reason| anyhow::anyhow!("dynamic path timestamp: {reason:?}"))?;
                }
            }
        }
        Ok(())
    }
}

pub(super) fn extract(uri: &str, index: usize) -> Result<String> {
    let uri: hyper::Uri = uri.parse()?;
    let segment = uri
        .path()
        .strip_prefix('/')
        .context("path must be absolute")?
        .split('/')
        .nth(index)
        .context("path segment absent")?;
    let decoded = super::http::percent_decode(segment)?;
    let value = String::from_utf8(decoded)?;
    ensure!(
        !value.is_empty()
            && value.len() <= 1024
            && !value
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\')),
        "invalid decoded path identity"
    );
    Ok(value)
}
