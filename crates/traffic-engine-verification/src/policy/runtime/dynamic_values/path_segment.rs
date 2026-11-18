//! Explicit path-segment templates: fixed components, shaped nonces and local clocks.
use anyhow::{Context, Result, ensure};
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
        #[serde(default)]
        mode: crate::policy::native::PathTimestampMode,
    },
}

fn utc_timezone() -> String {
    "UTC".into()
}
fn is_utc_timezone(value: &str) -> bool {
    value == "UTC"
}

#[allow(dead_code)]
enum Part<'a> {
    Literal(&'a str),
    Field(&'a str),
}

impl PathSegmentCapture {
    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
}
