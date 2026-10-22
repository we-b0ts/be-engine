use super::super::request_contract::{config as request, key as identity};
use super::*;

pub(super) fn convert(
    rule: &old::ReplayDependencyRule,
    inventory: &Inventory,
) -> Result<Vec<p::PolicyRule>> {
    let when = condition(rule.when.as_ref())?;
    let api = api(rule);
    let mut output = vec![];
    match rule.protocol {
        old::DependencyProtocol::Mysql => {
            let mysql = rule
                .mysql
                .as_ref()
                .context("fixture MySQL selector absent")?;
            let resource = inventory.resource(
                p::Protocol::Mysql,
                &rule.target,
                mysql.database.clone().map(p::Database::Name),
                mysql.username.clone(),
                None,
            )?;
            let selector = n::NativeMatch {
                api,
                resource: Some(resource),
                operation: Some(mysql.command.clone()),
                sql: Some(mysql.sql.clone()),
                tables: mysql.tables.clone(),
                table_patterns: mysql.table_patterns.clone(),
                table_series: mysql.table_series.clone(),
                ..Default::default()
            };
            let mut params = BTreeMap::new();
            let mut values = BTreeMap::new();
            for (slot, value) in &mysql.params {
                if let Some(time) = &value.time {
                    let mut time = time.clone();
                    if time.format.is_none() {
                        time.format = Some("%Y-%m-%d %H:%M:%S".into());
                    }
                    values.insert(
                        *slot,
                        proven(
                            n::SqlValueContract::Time(super::time(&time)?),
                            &rule.source_evidence,
                        ),
                    );
                } else {
                    params.insert(*slot, proven(generated(value)?, &rule.source_evidence));
                }
            }
            for (slot, value) in &mysql.sql_values {
                let value = match value {
                    old::MysqlTimeValueRule::Scalar(field) => {
                        n::SqlValueContract::Time(time(&field.time)?)
                    }
                    old::MysqlTimeValueRule::Json(fields) => n::SqlValueContract::Json {
                        fields: fields
                            .iter()
                            .map(|(path, field)| {
                                Ok((
                                    path.clone(),
                                    proven(time(&field.time)?, &field.source_evidence),
                                ))
                            })
                            .collect::<Result<_>>()?,
                    },
                };
                values.insert(*slot, proven(value, &rule.source_evidence));
            }
            let response_time = mysql
                .response_time_shift
                .iter()
                .map(|(column, field)| {
                    (
                        column.clone(),
                        proven(
                            n::SqlResponseTime {
                                time: n::NativeTime {
                                    format: p::TimestampFormat::SqlDatetime,
                                    relation: p::TimeRelation::PreserveOffset,
                                    anchor: p::TimeAnchor::DependencyRequestStart,
                                    utc_offset: Some("+00:00".into()),
                                    clock_group: None,
                                },
                                preserve_values: field.preserve_values.clone(),
                            },
                            &rule.source_evidence,
                        ),
                    )
                })
                .collect();
            output.push(
                native(
                    &rule.id,
                    selector,
                    n::NativeEffect::MysqlValues(n::MysqlValuesEffect {
                        params,
                        values,
                        response_time,
                    }),
                    &rule.source_evidence,
                    when,
                )
                .into(),
            );
        }
        old::DependencyProtocol::Http => {
            let http = rule.http.as_ref().context("fixture HTTP selector absent")?;
            let resource = inventory.resource(p::Protocol::Http, &rule.target, None, None, None)?;
            if rule.replay_scope == old::ReplayScope::RecordingRun {
                output.push(
                    native(
                        &rule.id,
                        n::NativeMatch {
                            resource: Some(resource),
                            operation: Some(http.method.clone()),
                            path: Some(http.path.clone()),
                            ..Default::default()
                        },
                        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http),
                        &rule.source_evidence,
                        when,
                    )
                    .into(),
                );
                return Ok(output);
            }
            if !http.json.is_empty() {
                let mut contract = http
                    .json
                    .unordered
                    .iter()
                    .map(|field| (field.pointer.clone(), p::FieldContract::Unordered))
                    .collect::<BTreeMap<_, _>>();
                contract.extend(http.json.time.iter().map(|(pointer, time)| {
                    (
                        pointer.clone(),
                        time_field(&n::NativeTime {
                            anchor: p::TimeAnchor::DependencyRequestStart,
                            ..request_time(time)
                        }),
                    )
                }));
                output.push(
                    value(
                        &rule.id,
                        p::Surface::DependencyRequest,
                        p::MatchSpec {
                            api: api.clone(),
                            resource: Some(resource.clone()),
                            operation: Some(http.method.clone()),
                            path: Some(http.path.clone()),
                            ..Default::default()
                        },
                        p::Slot::Body,
                        p::Codec::Json,
                        contract,
                        value_semantics(&rule.source_evidence, when.clone(), None),
                    )
                    .into(),
                );
            }
            if !http.headers.is_empty() || !http.query.is_empty() || http.multipart.is_some() {
                let headers = http
                    .headers
                    .iter()
                    .map(|(name, field)| {
                        (
                            name.clone(),
                            proven(
                                n::NativeTime {
                                    format: response::format(field.format()),
                                    relation: p::TimeRelation::RequestWindow,
                                    anchor: p::TimeAnchor::DependencyRequestStart,
                                    utc_offset: None,
                                    clock_group: None,
                                },
                                &rule.source_evidence,
                            ),
                        )
                    })
                    .collect();
                let query = http
                    .query
                    .iter()
                    .map(|(name, value)| {
                        let value = if let Some(time) = &value.time {
                            let mut time = time.clone();
                            if time.format.is_none() {
                                time.format = Some("%+".into());
                            }
                            n::GeneratedValue::Time(super::time(&time)?)
                        } else {
                            generated(value)?
                        };
                        Ok((name.clone(), proven(value, &rule.source_evidence)))
                    })
                    .collect::<Result<_>>()?;
                let id = if http.json.is_empty() {
                    rule.id.clone()
                } else {
                    format!("{}-envelope", rule.id)
                };
                output.push(
                    native(
                        &id,
                        n::NativeMatch {
                            api,
                            resource: Some(resource),
                            operation: Some(http.method.clone()),
                            path: Some(http.path.clone()),
                            ..Default::default()
                        },
                        n::NativeEffect::HttpRequest(n::HttpRequestEffect {
                            headers,
                            query,
                            json: Default::default(),
                            multipart_boundary: http.multipart.is_some(),
                        }),
                        &rule.source_evidence,
                        when,
                    )
                    .into(),
                );
            }
        }
        old::DependencyProtocol::Memcached => {
            let memcache = rule
                .memcached
                .as_ref()
                .context("fixture Memcached selector absent")?;
            let resource = inventory.resource(
                p::Protocol::Memcached,
                &rule.target,
                None,
                None,
                Some(memcache.resource.port()),
            )?;
            let fields = memcache
                .protobuf
                .timestamp_fields
                .keys()
                .map(|number| {
                    (
                        format!("/field_{number}"),
                        p::ProtobufField {
                            field_path: vec![*number],
                            field_type: p::ProtobufType::Uint64,
                            repeated: false,
                        },
                    )
                })
                .collect();
            let contract = memcache
                .protobuf
                .timestamp_fields
                .keys()
                .map(|number| {
                    (
                        format!("/field_{number}"),
                        p::FieldContract::Time {
                            format: p::TimestampFormat::UnixSeconds,
                            relation: p::TimeRelation::RequestWindow,
                            anchor: p::TimeAnchor::DependencyRequestStart,
                            utc_offset: None,
                            clock_group: None,
                        },
                    )
                })
                .collect();
            output.push(
                value(
                    &rule.id,
                    p::Surface::DependencyRequest,
                    p::MatchSpec {
                        api,
                        resource: Some(resource),
                        operation: Some(memcache.command.to_ascii_uppercase()),
                        key: Some(p::KeySelector {
                            prefix: (!memcache.key.prefix.is_empty())
                                .then(|| memcache.key.prefix.clone()),
                            suffix: (!memcache.key.suffix.is_empty())
                                .then(|| memcache.key.suffix.clone()),
                            numeric: true,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    p::Slot::Value,
                    p::Codec::Protobuf(p::ProtobufCodec { fields }),
                    contract,
                    value_semantics(&rule.source_evidence, when, None),
                )
                .into(),
            );
        }
        old::DependencyProtocol::Redis => {
            let redis = rule
                .redis
                .as_ref()
                .context("fixture Redis selector absent")?;
            let database = match redis {
                super::super::redis_value::RedisSelector::Requests(value) => value.database,
                super::super::redis_value::RedisSelector::TimeShift(value) => value.database,
                _ => 0,
            };
            let resource = inventory.resource(
                p::Protocol::Redis,
                &rule.target,
                Some(p::Database::Index(database)),
                None,
                None,
            )?;
            let mut selector = n::NativeMatch {
                api: api.clone(),
                resource: Some(resource.clone()),
                ..Default::default()
            };
            use super::super::redis_value::RedisSelector as R;
            match redis {
                R::Requests(request) => {
                    selector.key = Some(native_key(&request.key));
                    output.push(
                        native(
                            &rule.id,
                            selector,
                            n::NativeEffect::RedisSequence(sequence(
                                request,
                                &rule.source_evidence,
                            )?),
                            &rule.source_evidence,
                            when,
                        )
                        .into(),
                    );
                }
                R::Lock(lock) => {
                    selector.key = Some(native_key(&lock.lock.key));
                    output.push(
                        native(
                            &rule.id,
                            selector,
                            n::NativeEffect::RedisLock,
                            &lock.lock.source_evidence,
                            when,
                        )
                        .into(),
                    );
                }
                R::Publish(publish) => {
                    selector.operation = Some("PUBLISH".into());
                    selector.key = Some(n::NativeKeySelector::Exact {
                        value: publish.publish.channel.clone(),
                    });
                    output.push(
                        native(
                            &rule.id,
                            selector,
                            n::NativeEffect::RedisPublishIdentity(n::PublishIdentityEffect {
                                uuid_index: publish.publish.uuid_index,
                                uuid_field: publish.publish.uuid_field.clone(),
                            }),
                            &publish.publish.source_evidence,
                            when,
                        )
                        .into(),
                    );
                }
                R::TimeShift(read) => {
                    if rule.replay_scope == old::ReplayScope::RecordingRun {
                        selector.operation = Some(read.command.clone());
                        selector.key = Some(native_key(&read.key));
                        let response_time = read
                            .response_json
                            .iter()
                            .map(|(pointer, field)| {
                                (
                                    pointer.clone(),
                                    proven(
                                        redis_time(
                                            field.format,
                                            p::TimeAnchor::DependencyRequestStart,
                                        ),
                                        &rule.source_evidence,
                                    ),
                                )
                            })
                            .collect();
                        let hash_field = read
                            .hash_field
                            .as_ref()
                            .map(|field| match field {
                                crate::replay::RedisValueKeySelector::Exact { value } => {
                                    Ok(value.clone())
                                }
                                _ => {
                                    anyhow::bail!("test fixture shared field requires exact field")
                                }
                            })
                            .transpose()?;
                        output.push(
                            native(
                                &rule.id,
                                selector,
                                n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis {
                                    hash_field,
                                    response_time,
                                }),
                                &rule.source_evidence,
                                when,
                            )
                            .into(),
                        );
                    } else {
                        let contract = read
                            .response_json
                            .iter()
                            .map(|(pointer, field)| {
                                (
                                    pointer.clone(),
                                    time_field(&redis_time(
                                        field.format,
                                        p::TimeAnchor::DependencyRequestStart,
                                    )),
                                )
                            })
                            .collect::<BTreeMap<_, _>>();
                        let delivery = Some(p::Delivery {
                            rebase_time: contract.keys().cloned().collect(),
                        });
                        output.push(
                            value(
                                &rule.id,
                                p::Surface::DependencyResponse,
                                p::MatchSpec {
                                    api,
                                    resource: Some(resource),
                                    operation: Some(read.command.clone()),
                                    key: Some(key(&read.key)),
                                    hash_field: read.hash_field.as_ref().map(key),
                                    ..Default::default()
                                },
                                p::Slot::Value,
                                p::Codec::Json,
                                contract,
                                value_semantics(&rule.source_evidence, when, delivery),
                            )
                            .into(),
                        );
                    }
                }
                R::Value(value_rule) => {
                    let mut contract = BTreeMap::new();
                    let mut protobuf = BTreeMap::new();
                    let mut json = false;
                    for field in &value_rule.unordered {
                        match &field.field {
                            crate::replay::RedisUnorderedField::Json { pointer } => {
                                json = true;
                                contract.insert(pointer.clone(), p::FieldContract::Unordered);
                            }
                            crate::replay::RedisUnorderedField::Protobuf {
                                field_path,
                                element_type,
                                display_path,
                            } => {
                                let alias = if display_path.starts_with('/') {
                                    display_path.clone()
                                } else {
                                    format!("/{}", display_path.replace('.', "/"))
                                };
                                protobuf.insert(
                                    alias.clone(),
                                    p::ProtobufField {
                                        field_path: field_path.0.clone(),
                                        field_type: response::protobuf(*element_type).into(),
                                        repeated: true,
                                    },
                                );
                                contract.insert(alias, p::FieldContract::Unordered);
                            }
                        }
                    }
                    ensure!(
                        !json || protobuf.is_empty(),
                        "fixture cannot mix payload codecs"
                    );
                    output.push(
                        value(
                            &rule.id,
                            p::Surface::DependencyRequest,
                            p::MatchSpec {
                                api,
                                resource: Some(resource),
                                operation: Some("SET".into()),
                                key: Some(key(&value_rule.key)),
                                ..Default::default()
                            },
                            p::Slot::Value,
                            if json {
                                p::Codec::Json
                            } else {
                                p::Codec::Protobuf(p::ProtobufCodec { fields: protobuf })
                            },
                            contract,
                            value_semantics(&rule.source_evidence, when, None),
                        )
                        .into(),
                    );
                }
            }
        }
    }
    Ok(output)
}

fn generated(value: &old::DynamicValueRule) -> Result<n::GeneratedValue> {
    if let Some(reference) = &value.reference {
        return Ok(n::GeneratedValue::Reference {
            binding: reference.clone(),
        });
    }
    if let Some(time) = &value.time {
        return Ok(n::GeneratedValue::Time(super::time(time)?));
    }
    Ok(match value.validate {
        Some(old::ValueValidator::Uuid) => n::GeneratedValue::Uuid {
            binding: value.bind.clone(),
        },
        Some(old::ValueValidator::UuidV4) => n::GeneratedValue::UuidV4 {
            binding: value.bind.clone(),
        },
        Some(old::ValueValidator::NonEmpty) => n::GeneratedValue::NonEmpty {
            binding: value.bind.clone(),
        },
        None => n::GeneratedValue::Bind {
            binding: value
                .bind
                .clone()
                .context("generated fixture requires a binding or explicit validation")?,
        },
    })
}

fn sequence(value: &request::RedisRequestSelector, fact: &str) -> Result<n::RedisSequenceEffect> {
    let key = value.key_contract.as_ref().map(|key| {
        proven(
            match key {
                identity::KeyContract::TimeWindow {
                    window_seconds,
                    separator,
                    segment_index,
                } => n::NativeKeyContract::TimeWindow {
                    window_seconds: *window_seconds,
                    separator: *separator,
                    segment_index: *segment_index,
                },
                identity::KeyContract::Capture {
                    binding,
                    template,
                    format,
                } => n::NativeKeyContract::Capture {
                    binding: binding.clone(),
                    template: template.clone(),
                    format: match format {
                        identity::KeyFormat::Hex { bytes } => {
                            n::KeyIdentityFormat::Hex { bytes: *bytes }
                        }
                        identity::KeyFormat::Base64url { bytes } => {
                            n::KeyIdentityFormat::Base64url { bytes: *bytes }
                        }
                        identity::KeyFormat::UuidV4 => n::KeyIdentityFormat::UuidV4,
                    },
                },
                identity::KeyContract::Reference {
                    binding,
                    template,
                    transform,
                } => n::NativeKeyContract::Reference(n::IdentityReference {
                    binding: binding.clone(),
                    template: template.clone(),
                    transform: transform_kind(*transform),
                }),
            },
            fact,
        )
    });
    let commands = value
        .commands
        .iter()
        .map(|command| {
            let arguments = command
                .argument_values
                .iter()
                .map(|(slot, argument)| {
                    let argument = match argument {
                        request::ArgumentRule::Time(time) => {
                            n::SequenceArgument::Time(request_time(time))
                        }
                        request::ArgumentRule::Json(json) => n::SequenceArgument::Json {
                            fields: json
                                .json
                                .iter()
                                .map(|(pointer, field)| {
                                    let field = match field {
                                        request::JsonField::Time(time) => {
                                            n::SequenceField::Time(request_time(time))
                                        }
                                        request::JsonField::Identity(field) => {
                                            n::SequenceField::Identity(n::IdentityReference {
                                                binding: field.identity.binding.clone(),
                                                template: field.identity.template.clone(),
                                                transform: transform_kind(field.identity.transform),
                                            })
                                        }
                                        request::JsonField::Random(field) => {
                                            n::SequenceField::Random {
                                                format: field.random.format.clone(),
                                                length: field.random.length,
                                                max_length: field.random.max_length,
                                            }
                                        }
                                        request::JsonField::Url(field) => n::SequenceField::Url {
                                            query: field
                                                .url
                                                .iter()
                                                .map(|(name, field)| {
                                                    let field = match field {
                                                        request::UrlQueryField::Time(time) => {
                                                            n::SequenceUrlField::Time(request_time(
                                                                time,
                                                            ))
                                                        }
                                                        request::UrlQueryField::UtcDateSegment { utc_date_segment: segment } => n::SequenceUrlField::UtcDateSegment(segment.clone()),
                                                        request::UrlQueryField::Random(random) => {
                                                            n::SequenceUrlField::Random {
                                                                format: random
                                                                    .random
                                                                    .format
                                                                    .clone(),
                                                                length: random
                                                                    .random
                                                                    .length
                                                                    .context(
                                                                        "URL query requires length",
                                                                    )?,
                                                            }
                                                        }
                                                    };
                                                    Ok((name.clone(), proven(field, fact)))
                                                })
                                                .collect::<Result<_>>()?,
                                        },
                                        request::JsonField::Jwt(field) => n::SequenceField::Jwt {
                                            algorithm: algorithm(field.jwt.algorithm),
                                            signing_key: startup(&field.jwt.signing_key_source),
                                            relative_to: field.jwt.relative_to.clone(),
                                            nonces: field
                                                .jwt
                                                .dynamic_claims
                                                .iter()
                                                .map(|claim| {
                                                    Ok(proven(response::nonce(claim)?, fact))
                                                })
                                                .collect::<Result<_>>()?,
                                        },
                                    };
                                    Ok((pointer.clone(), proven(field, fact)))
                                })
                                .collect::<Result<_>>()?,
                        },
                    };
                    Ok((*slot, proven(argument, fact)))
                })
                .collect::<Result<_>>()?;
            Ok(n::SequenceCommand {
                operation: command.command.clone(),
                script: command.script.as_ref().map(|script| {
                    proven(
                        n::ScriptIdentity {
                            sha1: script.sha1.clone(),
                            sha256: script.sha256.clone(),
                        },
                        fact,
                    )
                }),
                arguments,
            })
        })
        .collect::<Result<_>>()?;
    Ok(n::RedisSequenceEffect {
        key,
        commands,
        read_back: vec![],
    })
}
fn transform_kind(value: identity::Transform) -> n::IdentityTransform {
    match value {
        identity::Transform::Identity => n::IdentityTransform::Identity,
        identity::Transform::Sha256 => n::IdentityTransform::Sha256,
    }
}
fn redis_time(
    value: crate::replay::redis::time_shift::RedisTimestampFormat,
    anchor: p::TimeAnchor,
) -> n::NativeTime {
    n::NativeTime {
        format: match value {
            crate::replay::redis::time_shift::RedisTimestampFormat::UnixSeconds => {
                p::TimestampFormat::UnixSeconds
            }
            crate::replay::redis::time_shift::RedisTimestampFormat::UnixMilliseconds => {
                p::TimestampFormat::UnixMilliseconds
            }
            crate::replay::redis::time_shift::RedisTimestampFormat::Rfc3339 => {
                p::TimestampFormat::Rfc3339
            }
        },
        anchor,
        relation: p::TimeRelation::PreserveOffset,
        utc_offset: None,
        clock_group: None,
    }
}
