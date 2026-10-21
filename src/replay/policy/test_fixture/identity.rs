use super::*;

pub(super) fn convert(rule: &d::DynamicValueRule, inventory: &Inventory) -> Result<n::NativeRule> {
    let mut selector = n::NativeMatch {
        api: Some(inventory.api(&rule.api)),
        ..Default::default()
    };
    let capture = match &rule.capture {
        d::DynamicValueCapture::Mysql {
            target,
            database,
            sql,
            tables,
            table_patterns,
            table_series,
            value_index,
            json_pointer,
        } => {
            selector.resource = Some(p::Resource {
                protocol: p::Protocol::Mysql,
                endpoint: p::Endpoint {
                    host: target.host.clone(),
                    port: target.port,
                },
                database: Some(p::Database::Name(database.clone())),
                username: None,
            });
            selector.sql = Some(sql.clone());
            selector.tables = tables.clone();
            selector.table_patterns = table_patterns.clone();
            selector.table_series = table_series.clone();
            n::IdentityCapture::MysqlValue {
                index: *value_index,
                json_pointer: json_pointer.clone(),
            }
        }
        d::DynamicValueCapture::Redis {
            target,
            database,
            command,
            key,
            argument_index,
            json_pointer,
            references,
            derived_from,
            when,
        } => {
            selector.resource = Some(p::Resource {
                protocol: p::Protocol::Redis,
                endpoint: p::Endpoint {
                    host: target.host.clone(),
                    port: target.port,
                },
                database: Some(p::Database::Index(*database)),
                username: None,
            });
            selector.operation = Some(command.clone());
            selector.key = Some(native_key(key));
            n::IdentityCapture::RedisArgument {
                index: *argument_index,
                when: when.clone(),
                json_pointer: json_pointer.clone(),
                copies: references
                    .iter()
                    .flatten()
                    .map(|copy| {
                        proven(
                            n::JsonIdentityCopy {
                                pointer: copy.json_pointer.clone(),
                                template: copy.template.clone(),
                            },
                            &rule.source_evidence,
                        )
                    })
                    .collect(),
                derived_from: derived_from.as_ref().map(|derived| {
                    proven(
                        n::DerivedIdentity {
                            pointer: derived.json_pointer.clone(),
                            prefix: derived.prefix.clone(),
                        },
                        &rule.source_evidence,
                    )
                }),
            }
        }
        d::DynamicValueCapture::Http {
            target,
            method,
            path,
            json_pointer,
            path_segment,
        } => {
            selector.resource = Some(p::Resource {
                protocol: p::Protocol::Http,
                endpoint: p::Endpoint {
                    host: target.host.clone(),
                    port: target.port,
                },
                database: None,
                username: None,
            });
            selector.operation = Some(method.clone());
            selector.path = Some(path.clone());
            if let Some(segment) = path_segment {
                n::IdentityCapture::HttpPath {
                    segment: n::PathIdentitySegment {
                        index: segment.index,
                        template: segment.template.clone(),
                        fields: segment
                            .fields
                            .iter()
                            .map(|(name, field)| {
                                let field = match field {
                                    d::PathSegmentField::Exact => n::PathIdentityField::Exact,
                                    d::PathSegmentField::Random { format, length } => {
                                        n::PathIdentityField::Random {
                                            format: if format == "hex" {
                                                n::PathRandomFormat::Hex
                                            } else {
                                                n::PathRandomFormat::Base64url
                                            },
                                            length: *length,
                                        }
                                    }
                                    d::PathSegmentField::Timestamp {
                                        format,
                                        timezone,
                                        mode,
                                    } => n::PathIdentityField::Timestamp {
                                        mode: *mode,
                                        format: format.clone(),
                                        timezone: timezone.clone(),
                                    },
                                };
                                (name.clone(), proven(field, &rule.source_evidence))
                            })
                            .collect(),
                    },
                }
            } else {
                n::IdentityCapture::HttpJson {
                    pointer: json_pointer
                        .clone()
                        .context("fixture HTTP capture pointer absent")?,
                }
            }
        }
    };
    let captured = selector.resource.as_ref().unwrap();
    let mut references: Vec<_> = rule
        .targets
        .iter()
        .map(|target| {
            let resource = if target.host.eq_ignore_ascii_case(&captured.endpoint.host)
                && target.port == captured.endpoint.port
            {
                captured.clone()
            } else {
                inventory
                    .resources
                    .iter()
                    .find(|resource| {
                        resource.endpoint.host.eq_ignore_ascii_case(&target.host)
                            && resource.endpoint.port == target.port
                    })
                    .cloned()
                    .unwrap_or(p::Resource {
                        protocol: if target.port == 6379 {
                            p::Protocol::Redis
                        } else if target.port == 3306 {
                            p::Protocol::Mysql
                        } else {
                            p::Protocol::Http
                        },
                        endpoint: p::Endpoint {
                            host: target.host.clone(),
                            port: target.port,
                        },
                        database: None,
                        username: None,
                    })
            };
            proven(n::IdentityTarget { resource }, &rule.source_evidence)
        })
        .collect();
    if rule.value_type == d::DynamicValueType::Integer {
        references.clear();
    }
    Ok(native(
        &rule.id,
        selector,
        n::NativeEffect::Identity(n::IdentityEffect {
            mysql_read_back: vec![],
            read_back: vec![],
            value_type: match rule.value_type {
                d::DynamicValueType::String => n::IdentityType::String,
                d::DynamicValueType::Integer => n::IdentityType::Integer,
            },
            format: rule.format.map(|format| match format {
                d::DynamicValueFormat::Uuid => n::IdentityFormat::Uuid,
                d::DynamicValueFormat::UuidV4 => n::IdentityFormat::UuidV4,
            }),
            capture,
            references,
        }),
        &rule.source_evidence,
        condition(rule.when.as_ref())?,
    ))
}
