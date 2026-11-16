//! Protocol selector adaptation preserves native effect state boundaries.
use anyhow::{Context, Result, ensure};

use super::super::{config as c, redis_value as r};
use super::*;
use crate::policy::{TimeAnchor, TimeRelation, TimestampFormat};

pub(super) fn project(rule: &n::NativeRule) -> Result<ReplayDependencyRule> {
    let mut projected = dependency_rule(rule)?;
    let selector = &rule.selector;
    let resource = selector.resource.as_ref();
    match &rule.effect {
        n::NativeEffect::RedisSequence(effect) => {
            projected.redis = Some(r::RedisSelector::Requests(
                super::super::request_contract::native_projection::sequence(rule, effect)?,
            ));
            projected.source_evidence = proof(rule.proof.as_ref());
        }
        n::NativeEffect::HttpRequest(effect) => {
            projected.http = Some(c::HttpSelector {
                multipart: effect.multipart_boundary.then_some(
                    super::super::request_contract::config::MultipartRule {
                        boundary:
                            super::super::request_contract::config::NormalizeBoundary::Normalize,
                    },
                ),
                method: selector
                    .operation
                    .clone()
                    .context("HTTP method is absent")?,
                path: selector.path.clone().context("HTTP path is absent")?,
                query: effect
                    .query
                    .iter()
                    .map(|(name, value)| {
                        Ok((
                            name.clone(),
                            match &value.contract {
                                n::GeneratedValue::Time(time) => {
                                    ensure!(
                                        matches!(
                                            time.anchor,
                                            TimeAnchor::Observation
                                                | TimeAnchor::DependencyRequestStart
                                        ),
                                        "HTTP query times require the corresponding dependency request start"
                                    );
                                    c::DynamicValueRule {
                                        bind: None,
                                        reference: None,
                                        validate: None,
                                        time: Some(sql_time(time)?),
                                    }
                                }
                                value => generated(value)?,
                            },
                        ))
                    })
                    .collect::<Result<_>>()?,
            });
        }
        n::NativeEffect::MysqlValues(effect) => {
            let resource = resource.context("MySQL dependency resource is absent")?;
            let sql_values = effect
                .values
                .iter()
                .map(|(index, value)| {
                    let value = match &value.contract {
                        n::SqlValueContract::Time(time) => {
                            c::MysqlTimeValueRule::Scalar(mysql_time(time, value.proof.as_ref())?)
                        }
                        n::SqlValueContract::Json { fields } => c::MysqlTimeValueRule::Json(
                            fields
                                .iter()
                                .map(|(pointer, value)| {
                                    Ok((
                                        pointer.clone(),
                                        mysql_time(&value.contract, value.proof.as_ref())?,
                                    ))
                                })
                                .collect::<Result<_>>()?,
                        ),
                    };
                    Ok((*index, value))
                })
                .collect::<Result<_>>()?;
            projected.mysql = Some(c::MysqlSelector {
                command: selector
                    .operation
                    .clone()
                    .unwrap_or_else(|| "COM_QUERY".into()),
                sql: selector
                    .sql
                    .clone()
                    .context("MySQL SQL selector is absent")?,
                tables: selector.tables.clone(),
                table_patterns: selector.table_patterns.clone(),
                table_series: selector.table_series.clone(),
                database: resource
                    .database
                    .as_ref()
                    .and_then(crate::policy::Database::name)
                    .map(str::to_owned),
                username: resource.username.clone(),
                params: effect
                    .params
                    .iter()
                    .map(|(index, value)| Ok((*index, generated(&value.contract)?)))
                    .collect::<Result<_>>()?,
                sql_values,
            });
        }
        n::NativeEffect::FiniteSharing(effect) => {
            projected.replay_scope = ReplayScope::RecordingRun;
            projected.source_evidence = proof(rule.proof.as_ref());
            match effect {
                n::FiniteSharingEffect::Http => {
                    projected.http = Some(c::HttpSelector {
                        multipart: None,
                        method: selector
                            .operation
                            .clone()
                            .context("shared HTTP method is absent")?,
                        path: selector
                            .path
                            .clone()
                            .context("shared HTTP path is absent")?,
                        query: BTreeMap::new(),
                    })
                }
                n::FiniteSharingEffect::Redis { hash_field } => {
                    projected.redis = Some(r::RedisSelector::SharedRead(
                        traffic_protocol_redis::bindings::RedisSharedRead {
                            command: selector
                                .operation
                                .clone()
                                .context("shared Redis command is absent")?,
                            database: resource
                                .and_then(|resource| resource.database.as_ref())
                                .and_then(crate::policy::Database::index),
                            key: key(selector
                                .key
                                .as_ref()
                                .context("shared Redis key is absent")?),
                            hash_field: hash_field.as_ref().map(|field| {
                                crate::RedisValueKeySelector::Exact {
                                    value: field.clone(),
                                }
                            }),
                        },
                    ));
                }
            }
        }
        _ => anyhow::bail!("native effect is not a dependency-runtime effect"),
    }
    Ok(projected)
}

pub(crate) fn generated(value: &n::GeneratedValue) -> Result<c::DynamicValueRule> {
    let mut result = c::DynamicValueRule {
        bind: None,
        reference: None,
        validate: None,
        time: None,
    };
    match value {
        n::GeneratedValue::Uuid {} => {
            result.validate = Some(c::ValueValidator::Uuid);
            result.bind = Some("automatic".into());
        }
        n::GeneratedValue::UuidV4 {} => {
            result.validate = Some(c::ValueValidator::UuidV4);
            result.bind = Some("automatic".into());
        }
        n::GeneratedValue::NonEmpty {} => {
            result.bind = Some("automatic".into());
            result.validate = Some(c::ValueValidator::NonEmpty);
        }
        n::GeneratedValue::Time(_) => {
            anyhow::bail!("typed time contracts use MySQL values or value codecs")
        }
    }
    Ok(result)
}

fn mysql_time(
    value: &n::NativeTime,
    source: Option<&crate::policy::Proof>,
) -> Result<c::MysqlTimeFieldRule> {
    ensure!(
        matches!(
            value.anchor,
            TimeAnchor::Observation | TimeAnchor::DependencyRequestStart
        ),
        "SQL request times require the corresponding dependency request start"
    );
    Ok(c::MysqlTimeFieldRule {
        source_evidence: proof(source),
        time: sql_time(value)?,
        anchor: value.anchor,
    })
}

fn sql_time(value: &n::NativeTime) -> Result<c::TimeRule> {
    ensure!(
        value.relation == TimeRelation::PreserveOffset,
        "SQL inventory projection requires preserve_offset"
    );
    let format = match value.format {
        TimestampFormat::UnixSeconds
        | TimestampFormat::UnixMilliseconds
        | TimestampFormat::UnixMicroseconds => None,
        TimestampFormat::Rfc3339 => Some("%+".into()),
        TimestampFormat::Iso8601Naive => Some("%Y-%m-%dT%H:%M:%S%.f".into()),
        TimestampFormat::SqlDatetime => Some("%Y-%m-%d %H:%M:%S%.f".into()),
        TimestampFormat::AmzDate => Some("%Y%m%dT%H%M%SZ".into()),
        TimestampFormat::CalendarDate => {
            anyhow::bail!("calendar_date requires a value codec contract")
        }
    };
    Ok(c::TimeRule {
        relative_to: c::TimeReference::PreserveRelative,
        offset: "0s".into(),
        tolerance: "5s".into(),
        format,
        timezone: value.utc_offset.clone(),
    })
}

pub(super) fn response_format(
    value: TimestampFormat,
) -> Result<super::super::response::ResponseTimestampFormat> {
    Ok(match value {
        TimestampFormat::UnixSeconds => {
            super::super::response::ResponseTimestampFormat::UnixSeconds
        }
        TimestampFormat::UnixMilliseconds => {
            super::super::response::ResponseTimestampFormat::UnixMilliseconds
        }
        TimestampFormat::Rfc3339 => super::super::response::ResponseTimestampFormat::Rfc3339,
        TimestampFormat::AmzDate => super::super::response::ResponseTimestampFormat::AmzDate,
        _ => anyhow::bail!("timestamp format is unsupported by this response domain"),
    })
}
