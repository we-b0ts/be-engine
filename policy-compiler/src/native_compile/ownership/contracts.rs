//! Contextual native relationships may refine an already owned field strategy.
use super::*;
use crate::{FieldContract, TimeContract};

fn time(value: &TimeContract) -> FieldContract {
    FieldContract::Time {
        format: value.format,
        relation: value.relation,
        anchor: value.anchor,
        utc_offset: value.utc_offset.clone(),
        clock_group: value.clock_group.clone(),
        clock_scope: value.clock_scope.clone(),
    }
}

pub fn native_contract(rule: &NativeRule, claim: &NativeFieldClaim) -> Option<FieldContract> {
    match &rule.effect {
        NativeEffect::MysqlValues(effect) => match &claim.slot {
            NativeOwnedSlot::SqlValue(index) => match &effect.values.get(index)?.contract {
                SqlValueContract::Time(value) if claim.location == OwnedLocation::Scalar => {
                    Some(time(value))
                }
                SqlValueContract::Json { fields } => {
                    let OwnedLocation::JsonPointer { pointer } = &claim.location else {
                        return None;
                    };
                    Some(time(&fields.get(pointer)?.contract))
                }
                _ => None,
            },
            _ => None,
        },
        NativeEffect::RedisSequence(effect) => effect.commands.iter().find_map(|command| {
            if Some(command.operation.as_str()) != claim.selector.operation.as_deref() {
                return None;
            }
            command.arguments.iter().find_map(|(index, argument)| {
                if redis_argument(&command.operation, *index) != claim.slot {
                    return None;
                }
                match &argument.contract {
                    SequenceArgument::Time(value) if claim.location == OwnedLocation::Scalar => {
                        Some(time(value))
                    }
                    SequenceArgument::Json { fields } => {
                        let OwnedLocation::JsonPointer { pointer } = &claim.location else {
                            return None;
                        };
                        match &fields.get(pointer)?.contract {
                            SequenceField::Time(value) => Some(time(value)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            })
        }),
        _ => None,
    }
}

pub fn same_strategy(left: &FieldContract, right: &FieldContract) -> bool {
    fn normalized(value: &FieldContract) -> FieldContract {
        let value = match value {
            FieldContract::Conditional { when, contract }
                if when.relative_pointer == "."
                    && matches!(contract.as_ref(), FieldContract::Time { .. }) =>
            {
                contract.as_ref()
            }
            value => value,
        };
        let mut value = value.clone();
        if let FieldContract::Time { clock_group, .. } = &mut value {
            *clock_group = None;
        }
        value
    }
    normalized(left) == normalized(right)
}

pub fn same_position(declared: &NativeFieldClaim, contextual: &NativeFieldClaim) -> bool {
    match &declared.slot {
        NativeOwnedSlot::SqlField(column) => {
            let Some(sql) = &contextual.selector.sql else {
                return false;
            };
            const MARKER: &str = "__traffic_field_table__";
            let template_marker = sql.contains("{{table}}") && !sql.contains(MARKER);
            let Some(tokens) = traffic_protocol_mysql_sql::sql::bounds::statement(
                &sql.replace("{{table}}", MARKER),
            ) else {
                return false;
            };
            let database = contextual
                .selector
                .resource
                .as_ref()
                .and_then(|r| r.database.as_ref())
                .and_then(crate::Database::name);
            let Ok(tables) = traffic_protocol_mysql_sql::table_selector::TableMatcher::new(
                &declared.selector.tables,
                &declared.selector.table_patterns,
                declared.selector.table_series.as_ref(),
            ) else {
                return false;
            };
            let matches =
                |field: &traffic_protocol_mysql_sql::sql::field_bindings::FieldIdentity| {
                    column.eq_ignore_ascii_case(&field.column)
                        && (template_marker && field.table == MARKER
                            || tables.matches(&field.table))
                        && declared
                            .selector
                            .resource
                            .as_ref()
                            .and_then(|r| r.database.as_ref())
                            .and_then(crate::Database::name)
                            .zip(field.database.as_deref())
                            .is_some_and(|(a, b)| a == b)
                };
            match &contextual.slot {
                NativeOwnedSlot::SqlValue(index) => {
                    let Some(position) = tokens
                        .iter()
                        .enumerate()
                        .filter(|(_, token)| {
                            matches!(token, traffic_protocol_mysql_sql::sql::Token::Placeholder)
                        })
                        .nth(*index)
                        .map(|(index, _)| index)
                    else {
                        return false;
                    };
                    traffic_protocol_mysql_sql::sql::field_bindings::resolve(&tokens, database)
                        .is_some_and(|fields| {
                            fields
                                .iter()
                                .any(|field| field.token_index == position && matches(&field.field))
                        })
                }
                NativeOwnedSlot::SqlColumn(name) => {
                    traffic_protocol_mysql_sql::sql::field_bindings::projection_columns(
                        &tokens, database,
                    )
                    .is_some_and(|columns| {
                        let original = columns
                            .iter()
                            .filter_map(|(_, field)| field.as_ref())
                            .filter(|field| field.column.eq_ignore_ascii_case(name))
                            .collect::<Vec<_>>();
                        if !original.is_empty() {
                            return original.len() == 1 && matches(original[0]);
                        }
                        let aliases = columns
                            .iter()
                            .filter(|(label, _)| label.eq_ignore_ascii_case(name))
                            .collect::<Vec<_>>();
                        aliases.len() == 1 && aliases[0].1.as_ref().is_some_and(matches)
                    })
                }
                _ => false,
            }
        }
        NativeOwnedSlot::RedisValue(container) => {
            use crate::RedisContainer;
            match (
                container,
                contextual.selector.operation.as_deref(),
                &contextual.slot,
            ) {
                (
                    RedisContainer::String,
                    Some("SET" | "SETEX" | "PSETEX"),
                    NativeOwnedSlot::Value,
                ) => true,
                (
                    RedisContainer::String,
                    Some("GET" | "MGET" | "GETEX" | "GETDEL"),
                    NativeOwnedSlot::Value,
                ) => contextual.surface == ClaimSurface::DependencyResponse,
                (
                    RedisContainer::String,
                    Some("MSET" | "MSETNX"),
                    NativeOwnedSlot::RedisArgument(index),
                ) => index % 2 == 1,
                (
                    RedisContainer::List,
                    Some("LPUSH" | "RPUSH" | "LPUSHX" | "RPUSHX"),
                    NativeOwnedSlot::RedisArgument(index),
                ) => *index >= 1,
                (RedisContainer::List, Some("LSET"), NativeOwnedSlot::RedisArgument(2)) => true,
                (
                    RedisContainer::Hash,
                    Some("HSET" | "HMSET"),
                    NativeOwnedSlot::RedisArgument(index),
                ) => declared.hash_field.is_none() && *index >= 2 && index % 2 == 0,
                (
                    RedisContainer::Hash,
                    Some("HGET" | "HMGET" | "HGETALL" | "HSCAN"),
                    NativeOwnedSlot::Value,
                ) => {
                    contextual.surface == ClaimSurface::DependencyResponse
                        && (declared.hash_field.is_none() || contextual.hash_field.is_some())
                }
                _ => false,
            }
        }
        _ => false,
    }
}
