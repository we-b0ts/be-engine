//! One source-proven capture location and explicit endpoints for automatic references.
pub use super::path_segment::{PathSegmentCapture, PathSegmentField};
pub use super::redis_json::{RedisCaptureReference, RedisDerivedIdentity};
use crate::RedisValueKeySelector;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueTarget {
    pub host: String,
    pub port: u16,
}

impl DynamicValueTarget {
    pub(super) fn matches(&self, target: &crate::replay::TargetKey) -> bool {
        self.port == target.port && self.host.eq_ignore_ascii_case(&target.host)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty()
                && self.host.len() <= 255
                && !self.host.contains(char::is_whitespace)
                && self.port > 0,
            "dynamic values require an exact host and nonzero port"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum DynamicValueCapture {
    Mysql {
        target: DynamicValueTarget,
        database: String,
        sql: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tables: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        table_patterns: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        table_series: Option<crate::MysqlTableSeries>,
        value_index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
    },
    Redis {
        target: DynamicValueTarget,
        database: i64,
        command: String,
        key: RedisValueKeySelector,
        argument_index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        when: Option<crate::policy::FieldCondition>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        references: Option<Vec<RedisCaptureReference>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derived_from: Option<RedisDerivedIdentity>,
    },
    Http {
        target: DynamicValueTarget,
        method: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        json_pointer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_segment: Option<PathSegmentCapture>,
    },
}

impl DynamicValueCapture {
    pub(crate) fn mysql_template(&self) -> Result<super::super::sql_template::SqlValueTemplate> {
        let Self::Mysql {
            sql,
            tables,
            table_patterns,
            table_series,
            ..
        } = self
        else {
            anyhow::bail!("MySQL capture template requires MySQL capture");
        };
        super::super::sql_template::SqlValueTemplate::new(
            sql,
            tables,
            table_patterns,
            table_series.as_ref(),
        )
    }

    pub(super) fn target(&self) -> &DynamicValueTarget {
        match self {
            Self::Mysql { target, .. } | Self::Redis { target, .. } | Self::Http { target, .. } => {
                target
            }
        }
    }
    fn validate(&self) -> Result<()> {
        self.target().validate()?;
        match self {
            Self::Mysql {
                database,
                value_index,
                json_pointer,
                ..
            } => {
                ensure!(
                    !database.is_empty() && database.len() <= 255,
                    "dynamic MySQL capture requires a database"
                );
                let template = self.mysql_template()?;
                let tokens = template.tokens();
                ensure!(
                    tokens
                        .first()
                        .is_some_and(|token| ["select", "insert", "update", "delete"]
                            .iter()
                            .any(|verb| token.is(verb))),
                    "dynamic capture requires a business SQL template"
                );
                ensure!(
                    *value_index
                        < tokens
                            .iter()
                            .filter(|token| **token == crate::mysql::sql::Token::Placeholder)
                            .count(),
                    "dynamic capture value_index exceeds SQL template slots"
                );
                if let Some(pointer) = json_pointer {
                    validate_pointer(pointer)?;
                }
            }
            Self::Redis {
                database,
                command,
                key,
                argument_index,
                when,
                json_pointer,
                references,
                derived_from,
                ..
            } => {
                ensure!(
                    *database >= 0,
                    "dynamic Redis capture requires a nonnegative database"
                );
                key.validate()?;
                ensure!(
                    command == "SET" && *argument_index == 1
                        || command == "LSET" && *argument_index == 2
                        || command == "HSET"
                            && *argument_index >= 2
                            && *argument_index <= 128
                            && argument_index.is_multiple_of(2)
                        || command == "RPUSH" && (1..=128).contains(argument_index),
                    "Redis capture selects SET value, LSET element index 2, HSET value, or RPUSH element indices 1..128"
                );
                if let Some(pointer) = json_pointer {
                    validate_pointer(pointer)?;
                }
                if let Some(when) = when {
                    when.validate(
                        json_pointer
                            .as_deref()
                            .context("conditional Redis identity requires a JSON pointer")?,
                    )?;
                }
                super::redis_json::validate(
                    json_pointer.as_deref(),
                    references.as_deref(),
                    derived_from.as_ref(),
                    key,
                )?;
            }
            Self::Http {
                method,
                path,
                json_pointer,
                path_segment,
                ..
            } => {
                ensure!(
                    method.len() <= 32
                        && method.parse::<hyper::Method>().is_ok()
                        && method.bytes().all(|byte| byte.is_ascii_uppercase()),
                    "dynamic HTTP capture requires an uppercase method"
                );
                crate::path_pattern::validate_path_pattern(path)?;
                ensure!(
                    json_pointer.is_some() != path_segment.is_some(),
                    "HTTP capture requires exactly one json_pointer or path_segment"
                );
                if let Some(pointer) = json_pointer {
                    validate_pointer(pointer)?;
                }
                if let Some(segment) = path_segment {
                    segment.validate(path)?;
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_pointer(pointer: &str) -> Result<()> {
    super::super::response::validate_json_pointer(pointer)?;
    ensure!(
        !pointer.split('/').any(|part| part == "*"),
        "dynamic capture JSON pointer must be exact"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicValueFormat {
    Uuid,
    UuidV4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicValueType {
    #[default]
    String,
    Integer,
}

impl DynamicValueType {
    fn is_string(&self) -> bool {
        *self == Self::String
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueRule {
    #[serde(default, skip_serializing_if = "DynamicValueType::is_string")]
    pub value_type: DynamicValueType,
    pub id: String,
    /// Empty means resource scope; native guards retain protocol/Case ownership.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<super::super::case_condition::CaseCondition>,
    pub targets: Vec<DynamicValueTarget>,
    pub capture: DynamicValueCapture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<DynamicValueFormat>,
    #[serde(default)]
    pub source_evidence: String,
}

impl DynamicValueRule {
    pub(super) fn matches_route(&self, path: &str) -> bool {
        self.api.is_empty() || super::super::pattern::path_pattern_matches(&self.api, path)
    }

    #[cfg(test)]
    fn overlaps_route(&self, other: &Self) -> bool {
        self.api.is_empty()
            || other.api.is_empty()
            || crate::path_pattern::path_patterns_overlap(&self.api, &other.api)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid dynamic value rule id"
        );
        ensure!(
            self.api.is_empty()
                || matches!(
                    self.api
                        .parse::<crate::recording_api::RecordingApiScope>()?,
                    crate::recording_api::RecordingApiScope::Route(_)
                ),
            "dynamic value API must be an HTTP route"
        );
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= 32,
            "dynamic values require 1-32 scoped endpoints"
        );
        for target in &self.targets {
            target.validate()?;
        }
        self.capture.validate()?;
        if let Some(condition) = &self.when {
            condition.validate()?;
        }
        ensure!(
            self.value_type == DynamicValueType::String
                || !matches!(
                    &self.capture,
                    DynamicValueCapture::Redis {
                        references: Some(_),
                        ..
                    }
                ),
            "explicit Redis JSON references require a string identity"
        );
        ensure!(
            self.value_type == DynamicValueType::String
                || matches!(
                    &self.capture,
                    DynamicValueCapture::Http {
                        json_pointer: Some(_),
                        ..
                    } | DynamicValueCapture::Redis {
                        json_pointer: Some(_),
                        ..
                    }
                ) && self.format.is_none(),
            "integer dynamic values require an HTTP or Redis JSON capture without a string format"
        );
        let target = self.capture.target();
        ensure!(
            self.targets.iter().any(|endpoint| endpoint == target),
            "dynamic capture endpoint must belong to targets"
        );
        crate::config::process_owned_dependencies::validate_optional_source_evidence(
            &self.source_evidence,
        )?;
        Ok(())
    }

    pub(crate) fn validate_value(&self, value: &str) -> Result<()> {
        if self.value_type == DynamicValueType::Integer {
            let value: serde_json::Value = serde_json::from_str(value)?;
            ensure!(
                value.is_i64() || value.is_u64(),
                "dynamic identity must be a JSON integer"
            );
            return Ok(());
        }
        ensure!(
            !value.is_empty() && value.len() <= 1024,
            "dynamic identities must be nonempty strings of at most 1024 bytes"
        );
        if let Some(format) = self.format {
            let uuid = uuid::Uuid::parse_str(value)?;
            ensure!(
                format != DynamicValueFormat::UuidV4 || uuid.get_version_num() == 4,
                "dynamic identity must be UUID v4"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn validate(rules: &[DynamicValueRule]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    ensure!(
        rules.len() <= 64,
        "at most 64 dynamic value rules are supported"
    );
    for (index, rule) in rules.iter().enumerate() {
        rule.validate()?;
        ensure!(ids.insert(&rule.id), "duplicate dynamic value rule id");
        for other in &rules[..index] {
            if !super::super::case_condition::overlaps(rule.when.as_ref(), other.when.as_ref()) {
                continue;
            }
            if let (
                DynamicValueCapture::Mysql {
                    target: a,
                    database: ad,
                    value_index: ai,
                    json_pointer: ap,
                    ..
                },
                DynamicValueCapture::Mysql {
                    target: b,
                    database: bd,
                    value_index: bi,
                    json_pointer: bp,
                    ..
                },
            ) = (&rule.capture, &other.capture)
                && a.host.eq_ignore_ascii_case(&b.host)
                && a.port == b.port
                && ad == bd
                && rule.overlaps_route(other)
            {
                let left = rule.capture.mysql_template()?;
                let right = other.capture.mysql_template()?;
                let position = |template: &super::super::sql_template::SqlValueTemplate, index| {
                    template
                        .tokens()
                        .iter()
                        .enumerate()
                        .filter(|(_, token)| **token == crate::mysql::sql::Token::Placeholder)
                        .nth(index)
                        .map(|(position, _)| position)
                };
                let fields_overlap = match (ap, bp) {
                    (Some(a), Some(b)) => super::super::response_locations_overlap(a, b),
                    _ => true,
                };
                ensure!(
                    !(fields_overlap
                        && position(&left, *ai) == position(&right, *bi)
                        && left.overlaps(&right)),
                    "overlapping dynamic MySQL capture location"
                );
            }
            if let (
                DynamicValueCapture::Redis {
                    target: a,
                    database: ad,
                    command: am,
                    key: ak,
                    argument_index: ai,
                    json_pointer: ap,
                    references: ar,
                    when: aw,
                    ..
                },
                DynamicValueCapture::Redis {
                    target: b,
                    database: bd,
                    command: bm,
                    key: bk,
                    argument_index: bi,
                    json_pointer: bp,
                    references: br,
                    when: bw,
                    ..
                },
            ) = (&rule.capture, &other.capture)
            {
                if let (Some(a), Some(b), Some(aw), Some(bw)) = (ap, bp, aw, bw)
                    && aw.peer_pointer(a) == bw.peer_pointer(b)
                    && aw.disjoint(bw)
                {
                    continue;
                }
                let fields_overlap = match (ap, bp) {
                    (Some(a), Some(b)) => std::iter::once(a)
                        .chain(ar.iter().flatten().map(|reference| &reference.json_pointer))
                        .any(|left| {
                            std::iter::once(b)
                                .chain(br.iter().flatten().map(|reference| &reference.json_pointer))
                                .any(|right| super::super::response_locations_overlap(left, right))
                        }),
                    _ => true,
                };
                ensure!(
                    !(a.host.eq_ignore_ascii_case(&b.host)
                        && a.port == b.port
                        && ad == bd
                        && am == bm
                        && ai == bi
                        && fields_overlap
                        && ak.overlaps(bk)
                        && rule.overlaps_route(other)),
                    "overlapping dynamic Redis capture location"
                );
            }
            if let (
                DynamicValueCapture::Http {
                    target: a,
                    method: am,
                    path: ap,
                    path_segment: Some(ac),
                    ..
                },
                DynamicValueCapture::Http {
                    target: b,
                    method: bm,
                    path: bp,
                    path_segment: Some(bc),
                    ..
                },
            ) = (&rule.capture, &other.capture)
            {
                ensure!(
                    !(a.host.eq_ignore_ascii_case(&b.host)
                        && a.port == b.port
                        && am == bm
                        && ac.index == bc.index
                        && rule.overlaps_route(other)
                        && crate::path_pattern::path_patterns_overlap(ap, bp)),
                    "overlapping dynamic path capture location"
                );
            }
        }
        ensure!(
            !rules[..index]
                .iter()
                .any(|other| super::super::case_condition::overlaps(
                    other.when.as_ref(),
                    rule.when.as_ref()
                ) && rule.overlaps_route(other)
                    && other.capture == rule.capture),
            "duplicate dynamic value capture location"
        );
    }
    Ok(())
}
