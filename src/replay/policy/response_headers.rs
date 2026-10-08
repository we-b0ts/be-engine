//! Explicit calendar-date locations in HTTP response headers.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderDateRule {
    pub header: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    pub format: String,
    pub timezone: String,
    #[serde(default)]
    pub source_evidence: String,
}

pub(in crate::replay) type ResponseHeaderRules = BTreeMap<String, Vec<ResponseHeaderDateRule>>;

impl ResponseHeaderDateRule {
    pub(in crate::replay) fn id(&self, api: &str) -> String {
        format!(
            "header-date:{api}:{}:{}",
            self.header.to_ascii_lowercase(),
            self.parameter
                .as_deref()
                .unwrap_or("$")
                .to_ascii_lowercase()
        )
    }

    pub(in crate::replay) fn validate(&self) -> Result<()> {
        ensure!(
            crate::http::response_headers::STANDARD_RESPONSE_HEADERS
                .iter()
                .any(|name| self.header.eq_ignore_ascii_case(name)),
            "response header date rule must select a captured standard header"
        );
        ensure!(
            self.parameter.as_ref().is_none_or(|name| {
                !name.is_empty()
                    && name.len() <= 128
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*')
                    })
            }),
            "invalid response header parameter"
        );
        ensure!(
            matches!(
                self.format.as_str(),
                "%Y-%m-%d" | "%Y%m%d" | "%Y/%m/%d" | "%d-%m-%Y" | "%m-%d-%Y"
            ),
            "response header date format must be a supported fixed-width calendar date"
        );
        super::config::parse_timezone(&self.timezone)?;
        crate::config::process_owned_dependencies::validate_source_evidence(&self.source_evidence)?;
        Ok(())
    }

    pub(in crate::replay) fn timezone_seconds(&self) -> Result<i32> {
        super::config::parse_timezone(&self.timezone)
    }
}

pub(in crate::replay) fn matches(api: &str, path: &str) -> bool {
    super::pattern::path_pattern_matches(api, path)
}

pub(in crate::replay) fn validate(rules: &ResponseHeaderRules) -> Result<()> {
    let mut selectors: Vec<(&str, String, String)> = Vec::new();
    for (api, entries) in rules {
        ensure!(
            matches!(
                api.parse::<crate::recording_api::RecordingApiScope>()?,
                crate::recording_api::RecordingApiScope::Route(_)
            ),
            "header date rules require an HTTP route selector"
        );
        ensure!(
            !entries.is_empty() && entries.len() <= 32,
            "response header rules must contain 1-32 date selectors"
        );
        let mut selected = BTreeSet::new();
        for rule in entries {
            rule.validate()?;
            let header = rule.header.to_ascii_lowercase();
            let parameter = rule
                .parameter
                .as_deref()
                .unwrap_or("$")
                .trim_end_matches('*')
                .to_ascii_lowercase();
            ensure!(
                selected.insert((header.clone(), parameter.clone())),
                "overlapping response header date selectors"
            );
            ensure!(
                !selected.iter().any(|(h, p)| h == &header
                    && p != &parameter
                    && (p == "$" || parameter == "$")),
                "whole-header and parameter date selectors overlap"
            );
            ensure!(
                !selectors
                    .iter()
                    .any(
                        |(other_api, other_header, other_parameter)| other_header == &header
                            && (other_parameter == &parameter
                                || other_parameter == "$"
                                || parameter == "$")
                            && crate::path_pattern::path_patterns_overlap(other_api, api)
                    ),
                "response header date selectors overlap across API patterns"
            );
            selectors.push((api, header, parameter));
        }
    }
    Ok(())
}
