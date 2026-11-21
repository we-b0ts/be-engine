use super::*;
use crate::policy::{Database, Endpoint, Protocol, Resource};

pub(super) fn rule(value: &B, proof: &Proof) -> Result<n::NativeRule> {
    let selector = match value {
        B::RedisScript { selector, .. } => n::ProcessSelector::RedisScript(selector.clone()),
        B::RedisPubsub { selector, .. } => n::ProcessSelector::RedisPubsub(selector.clone()),
        B::RedisPublish { selector, .. } => n::ProcessSelector::Redis {
            ports: selector.ports.clone(),
            operation: "PUBLISH".into(),
            keys: selector
                .channels
                .iter()
                .map(|value| n::NativeKeySelector::Exact {
                    value: value.clone(),
                })
                .collect(),
            key_templates: Vec::new(),
            key_sequence: Vec::new(),
            arguments: Vec::new(),
            script: None,
            initial_load_timeout_ms: None,
            fields: Vec::new(),
            when_message: selector.when_message.clone(),
        },
        B::Http {
            authorities,
            methods,
            path_prefixes,
            ..
        } => n::ProcessSelector::Http {
            authorities: authorities.clone(),
            methods: methods.clone(),
            path_prefixes: path_prefixes.clone(),
        },
        B::Memcached {
            breeze_identity,
            command,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            initial_load_timeout_ms,
            ..
        } => n::ProcessSelector::Memcached {
            breeze_identity: breeze_identity.clone(),
            operation: command.clone(),
            key_start: *key_start,
            key_end: *key_end,
            key_separator: key_separator.clone(),
            key_suffix: key_suffix.clone(),
            initial_load_timeout_ms: *initial_load_timeout_ms,
        },
        B::Motan {
            group,
            interface_name,
            method_name,
            ..
        } => n::ProcessSelector::Motan {
            group: group.clone(),
            interface: interface_name.clone(),
            method: method_name.clone(),
        },
        B::Mysql {
            selector,
            include_transaction_boundaries,
            transaction_members,
            identity_value_index,
            ..
        } => n::ProcessSelector::Mysql {
            selector: mysql(selector),
            include_transaction_boundaries: *include_transaction_boundaries,
            identity_value_index: *identity_value_index,
            transaction_members: transaction_members
                .iter()
                .map(|member| Proven {
                    contract: mysql(member),
                    proof: Some(proof.clone()),
                })
                .collect(),
        },
        B::Redis {
            ports,
            command,
            keys,
            key_patterns,
            key_prefix,
            key_suffix,
            key_templates,
            key_sequence,
            arguments,
            script,
            initial_load_timeout_ms,
            fields,
            ..
        } => {
            let mut selectors = keys
                .iter()
                .map(|value| n::NativeKeySelector::Exact {
                    value: value.clone(),
                })
                .collect::<Vec<_>>();
            selectors.extend(key_patterns.iter().map(key));
            if !key_prefix.is_empty() || !key_suffix.is_empty() {
                selectors.push(n::NativeKeySelector::Affix {
                    prefix: key_prefix.clone(),
                    suffix: key_suffix.clone(),
                });
            }
            n::ProcessSelector::Redis {
                ports: ports.clone(),
                operation: command.clone(),
                keys: selectors,
                key_templates: key_templates.clone(),
                key_sequence: key_sequence.clone(),
                arguments: arguments.clone(),
                script: script.as_ref().map(|script| Proven {
                    contract: n::OriginScript {
                        sha1: script.sha1.clone(),
                        keys: script.keys.iter().map(script_key).collect(),
                        argv_count: script.argv_count,
                        identity_argv_index: script.identity_argv_index,
                    },
                    proof: Some(proof.clone()),
                }),
                initial_load_timeout_ms: *initial_load_timeout_ms,
                fields: fields.clone(),
                when_message: Default::default(),
            }
        }
    };
    let revision = match value {
        B::Http {
            source_revision, ..
        }
        | B::RedisPubsub {
            source_revision, ..
        }
        | B::RedisPublish {
            source_revision, ..
        }
        | B::RedisScript {
            source_revision, ..
        }
        | B::Mysql {
            source_revision, ..
        }
        | B::Redis {
            source_revision, ..
        }
        | B::Memcached {
            source_revision, ..
        }
        | B::Motan {
            source_revision, ..
        } => source_revision.clone(),
    };
    let origin = value
        .trigger_source()
        .map(|origin| origin::convert(origin, proof))
        .transpose()?;
    Ok(super::rule(
        value.name().into(),
        n::NativeEffect::ProcessOwned(n::ProcessOwnedEffect {
            task_name: None,
            source_revision: revision,
            selector,
            origin,
        }),
        proof,
    ))
}

pub(super) fn mysql(
    value: &super::super::super::MysqlBackgroundSelector,
) -> n::MysqlProcessSelector {
    n::MysqlProcessSelector {
        resource: Resource {
            protocol: Protocol::Mysql,
            endpoint: Endpoint {
                host: value.target_host.clone(),
                port: value.target_port,
            },
            database: Some(Database::Name(value.database.clone())),
            username: Some(value.username.clone()),
        },
        sql: value.sql.clone(),
        tables: value.tables.clone(),
        table_patterns: value.table_patterns.clone(),
        table_series: value.table_series.clone(),
    }
}
fn key(value: &RedisKeyPatternConfig) -> n::NativeKeySelector {
    if value.numeric_middle {
        n::NativeKeySelector::Numeric {
            prefix: value.prefix.clone(),
            suffix: value.suffix.clone(),
        }
    } else {
        n::NativeKeySelector::Affix {
            prefix: value.prefix.clone(),
            suffix: value.suffix.clone(),
        }
    }
}

fn script_key(value: &RedisKeyPatternConfig) -> n::NativeKeySelector {
    if value.numeric_middle {
        key(value)
    } else {
        // The Lua envelope owner requires an empty middle when this flag is
        // false. General process-key affixes have different semantics.
        n::NativeKeySelector::Exact {
            value: format!("{}{}", value.prefix, value.suffix),
        }
    }
}

#[cfg(test)]
mod tests;
