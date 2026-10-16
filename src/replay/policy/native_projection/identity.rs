//! Identity capture and shaped copies are bound by the existing atomic owner.
use anyhow::{Context, Result, ensure};

use super::super::dynamic_values as d;
use super::*;

pub(super) fn project(
    rule: &n::NativeRule,
    effect: &n::IdentityEffect,
) -> Result<d::DynamicValueRule> {
    let selector = &rule.selector;
    let resource = selector
        .resource
        .as_ref()
        .context("identity resource is absent")?;
    let target = d::DynamicValueTarget {
        host: resource.endpoint.host.clone(),
        port: resource.endpoint.port,
    };
    let capture = match &effect.capture {
        n::IdentityCapture::MysqlValue {
            index,
            json_pointer,
        } => d::DynamicValueCapture::Mysql {
            target: target.clone(),
            database: resource
                .database
                .as_ref()
                .and_then(crate::policy::Database::name)
                .context("identity MySQL database is absent")?
                .into(),
            sql: selector
                .sql
                .clone()
                .context("identity SQL selector is absent")?,
            tables: selector.tables.clone(),
            table_patterns: selector.table_patterns.clone(),
            table_series: selector.table_series.clone(),
            value_index: *index,
            json_pointer: json_pointer.clone(),
        },
        n::IdentityCapture::RedisArgument {
            index,
            json_pointer,
            copies,
            derived_from,
        } => d::DynamicValueCapture::Redis {
            target: target.clone(),
            database: resource
                .database
                .as_ref()
                .and_then(crate::policy::Database::index)
                .context("identity Redis database is absent")?,
            command: selector
                .operation
                .clone()
                .context("identity Redis operation is absent")?,
            key: key(selector
                .key
                .as_ref()
                .context("identity Redis key is absent")?),
            argument_index: *index,
            json_pointer: json_pointer.clone(),
            references: (!copies.is_empty()).then(|| {
                copies
                    .iter()
                    .map(|copy| d::RedisCaptureReference {
                        json_pointer: copy.contract.pointer.clone(),
                        template: copy.contract.template.clone(),
                    })
                    .collect()
            }),
            derived_from: derived_from
                .as_ref()
                .map(|derived| d::RedisDerivedIdentity {
                    json_pointer: derived.contract.pointer.clone(),
                    prefix: derived.contract.prefix.clone(),
                }),
        },
        n::IdentityCapture::HttpJson { pointer } => d::DynamicValueCapture::Http {
            target: target.clone(),
            method: selector
                .operation
                .clone()
                .context("HTTP capture method is absent")?,
            path: selector
                .path
                .clone()
                .context("HTTP capture path is absent")?,
            json_pointer: Some(pointer.clone()),
            path_segment: None,
        },
        n::IdentityCapture::HttpPath { segment } => d::DynamicValueCapture::Http {
            target: target.clone(),
            method: selector
                .operation
                .clone()
                .context("HTTP capture method is absent")?,
            path: selector
                .path
                .clone()
                .context("HTTP capture path is absent")?,
            json_pointer: None,
            path_segment: Some(d::PathSegmentCapture {
                index: segment.index,
                template: segment.template.clone(),
                fields: segment
                    .fields
                    .iter()
                    .map(|(name, field)| {
                        let field = match &field.contract {
                            n::PathIdentityField::Exact => d::PathSegmentField::Exact,
                            n::PathIdentityField::Random { format, length } => {
                                d::PathSegmentField::Random {
                                    format: match format {
                                        n::PathRandomFormat::Hex => "hex",
                                        n::PathRandomFormat::Base64url => "base64url",
                                    }
                                    .into(),
                                    length: *length,
                                }
                            }
                            n::PathIdentityField::Timestamp { format, timezone } => {
                                d::PathSegmentField::Timestamp {
                                    format: format.clone(),
                                    timezone: timezone.clone(),
                                }
                            }
                        };
                        (name.clone(), field)
                    })
                    .collect(),
            }),
        },
    };
    let (_, api) = selector
        .api
        .as_deref()
        .context("identity API selector is absent")?
        .split_once(' ')
        .context("identity API selector is invalid")?;
    let mut targets = effect
        .references
        .iter()
        .map(|reference| d::DynamicValueTarget {
            host: reference.contract.resource.endpoint.host.clone(),
            port: reference.contract.resource.endpoint.port,
        })
        .collect::<Vec<_>>();
    if effect.value_type == n::IdentityType::Integer {
        targets.push(target);
    } else {
        ensure!(
            effect
                .references
                .iter()
                .any(|reference| reference.contract.resource == *resource),
            "identity references must include the original capture resource"
        );
    }
    let output = d::DynamicValueRule {
        id: rule.id.clone(),
        api: api.into(),
        when: condition(rule.when.as_ref()),
        targets,
        capture,
        value_type: match effect.value_type {
            n::IdentityType::String => d::DynamicValueType::String,
            n::IdentityType::Integer => d::DynamicValueType::Integer,
        },
        format: effect.format.map(|format| match format {
            n::IdentityFormat::Uuid => d::DynamicValueFormat::Uuid,
            n::IdentityFormat::UuidV4 => d::DynamicValueFormat::UuidV4,
        }),
        source_evidence: proof(&rule.proof),
    };
    output.validate()?;
    Ok(output)
}
