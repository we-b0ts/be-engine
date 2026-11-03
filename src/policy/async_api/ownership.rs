//! Source-proven positive ownership of finite asynchronous dependency requests.
use crate::policy::{Proof, Protocol, Resource};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    pub origin: AsyncOriginCapture,
    pub requests: Vec<AsyncOwnershipRequest>,
}

/// All named identities are captured from the same unique committed INSERT row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncOriginCapture {
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub table_patterns: Vec<String>,
    #[serde(deserialize_with = "super::super::strict_map::unique_map")]
    pub row_match: BTreeMap<String, Value>,
    #[serde(deserialize_with = "super::super::strict_map::unique_map")]
    pub bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum AsyncOwnershipRequest {
    Mysql {
        resource: Resource,
        sql: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tables: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        table_patterns: Vec<String>,
        /// Zero-based scalar placeholder position to the captured identity name.
        #[serde(default, deserialize_with = "super::super::strict_map::unique_map")]
        bindings: BTreeMap<usize, String>,
        /// An explicitly proven ID-free member of a complete anchored transaction.
        #[serde(default, skip_serializing_if = "is_false")]
        transaction_member: bool,
    },
    Redis {
        resource: Resource,
        operation: String,
        arguments: Vec<AsyncOwnershipArgument>,
        #[serde(default, skip_serializing_if = "is_false")]
        script_exists_prelude: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AsyncOwnershipArgument {
    Literal(String),
    Identity(AsyncOwnershipIdentity),
    Json(AsyncOwnershipJson),
    Any(AsyncOwnershipAny),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncOwnershipIdentity {
    pub identity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub suffix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncOwnershipJson {
    #[serde(deserialize_with = "super::super::strict_map::unique_map")]
    pub json: BTreeMap<String, AsyncOwnershipJsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AsyncOwnershipJsonValue {
    Literal(AsyncOwnershipLiteral),
    Identity(AsyncOwnershipIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncOwnershipLiteral {
    pub literal: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncOwnershipAny {
    pub any: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn resource(resource: &Resource, protocol: Protocol) -> Result<()> {
    resource.endpoint.validate()?;
    ensure!(
        resource.protocol == protocol,
        "async ownership resource protocol differs"
    );
    ensure!(
        resource
            .username
            .as_ref()
            .is_some_and(|name| !name.is_empty() && name.len() <= 128),
        "async ownership requires an exact resource username"
    );
    ensure!(
        match protocol {
            Protocol::Mysql => resource
                .database
                .as_ref()
                .and_then(|value| value.name())
                .is_some_and(identifier),
            Protocol::Redis => resource
                .database
                .as_ref()
                .and_then(|value| value.index())
                .is_some_and(|index| index >= 0),
            _ => false,
        },
        "async ownership requires an exact physical database"
    );
    Ok(())
}

fn identity(value: &AsyncOwnershipIdentity, origin: &AsyncOriginCapture) -> Result<()> {
    ensure!(
        origin.bindings.contains_key(&value.identity),
        "unknown async ownership binding"
    );
    ensure!(
        value.prefix.len() + value.suffix.len() <= 1024,
        "async ownership identity affixes exceed bounds"
    );
    Ok(())
}

pub(crate) fn validate(ownership: &AsyncOwnership) -> Result<()> {
    if let Some(proof) = &ownership.proof {
        proof.validate(false)?;
    }
    let origin = &ownership.origin;
    resource(&origin.resource, Protocol::Mysql)?;
    crate::config::mysql_tables::TableMatcher::new(&origin.tables, &origin.table_patterns, None)?;
    ensure!(
        (1..=16).contains(&origin.row_match.len()) && (1..=8).contains(&origin.bindings.len()),
        "async origin requires bounded row predicates and 1..8 same-row bindings"
    );
    for (column, value) in &origin.row_match {
        ensure!(
            identifier(column)
                && (value.is_string() || value.as_u64().is_some() || value.as_i64().is_some()),
            "async origin row predicates require physical columns and string/integer literals"
        );
    }
    for (name, column) in &origin.bindings {
        ensure!(
            identifier(name) && identifier(column),
            "async origin requires bounded binding and column names"
        );
    }
    ensure!(
        (1..=256).contains(&ownership.requests.len()),
        "async ownership requires 1..256 request selectors"
    );
    for request in &ownership.requests {
        match request {
            AsyncOwnershipRequest::Mysql {
                resource: selected,
                sql,
                tables,
                table_patterns,
                bindings,
                transaction_member,
            } => {
                resource(selected, Protocol::Mysql)?;
                ensure!(
                    !sql.is_empty() && sql.len() <= 8192,
                    "async ownership SQL exceeds bounds"
                );
                crate::config::mysql_tables::TableMatcher::new(tables, table_patterns, None)?;
                let replaced = sql.replace("{{table}}", "__async_ownership_table__");
                let tokens = crate::mysql::sql::bounds::statement(&replaced)
                    .context("async ownership requires one bounded SQL statement")?;
                ensure!(
                    tokens
                        .first()
                        .is_some_and(|token| ["select", "update", "insert", "delete"]
                            .iter()
                            .any(|word| token.is(word))),
                    "async ownership SQL requires a concrete business statement"
                );
                let count = tokens
                    .iter()
                    .filter(|token| **token == crate::mysql::sql::Token::Placeholder)
                    .count();
                ensure!(
                    count <= 128 && bindings.keys().all(|index| *index < count),
                    "async ownership SQL binding is outside scalar placeholders"
                );
                ensure!(
                    !bindings.is_empty() || *transaction_member,
                    "ID-free SQL requires explicit transaction_member proof"
                );
                for name in bindings.values() {
                    ensure!(
                        origin.bindings.contains_key(name),
                        "unknown async ownership SQL binding"
                    );
                }
                for index in bindings.keys() {
                    let position = tokens
                        .iter()
                        .enumerate()
                        .filter(|(_, token)| **token == crate::mysql::sql::Token::Placeholder)
                        .nth(*index)
                        .map(|(position, _)| position)
                        .expect("validated placeholder");
                    let equality = position.checked_sub(2).is_some_and(|prior| {
                        matches!(
                            tokens[prior],
                            crate::mysql::sql::Token::Word(_)
                                | crate::mysql::sql::Token::Identifier(_)
                        ) && tokens[prior + 1].is("=")
                    }) && tokens.get(position + 1).is_none_or(|token| {
                        ["and", ")", "order", "limit", "group", "having"]
                            .iter()
                            .any(|word| token.is(word))
                    });
                    let singleton_in =
                        position.checked_sub(3).is_some_and(|prior| {
                            matches!(
                                tokens[prior],
                                crate::mysql::sql::Token::Word(_)
                                    | crate::mysql::sql::Token::Identifier(_)
                            ) && tokens[prior + 1].is("in")
                                && tokens[prior + 2].is("(")
                        }) && tokens.get(position + 1).is_some_and(|token| token.is(")"));
                    ensure!(
                        tokens
                            .iter()
                            .position(|token| token.is("where"))
                            .is_some_and(|where_position| position > where_position)
                            && !tokens.iter().any(|token| token.is("or") || token.is("not"))
                            && (equality || singleton_in),
                        "async ownership identity must bind a positive WHERE equality or singleton IN predicate without OR/NOT"
                    );
                }
            }
            AsyncOwnershipRequest::Redis {
                resource: selected,
                operation,
                arguments,
                script_exists_prelude,
            } => {
                resource(selected, Protocol::Redis)?;
                ensure!(
                    !operation.is_empty()
                        && operation.len() <= 64
                        && operation
                            .bytes()
                            .all(|byte| byte.is_ascii_uppercase() || byte == b'_'),
                    "async ownership Redis operation requires a concrete uppercase command"
                );
                ensure!(
                    (1..=128).contains(&arguments.len()),
                    "async ownership Redis arguments exceed bounds"
                );
                let mut bound = false;
                for argument in arguments {
                    match argument {
                        AsyncOwnershipArgument::Literal(value) => ensure!(
                            value.len() <= 8192,
                            "async ownership literal exceeds bounds"
                        ),
                        AsyncOwnershipArgument::Identity(value) => {
                            identity(value, origin)?;
                            bound = true;
                        }
                        AsyncOwnershipArgument::Any(value) => {
                            ensure!(value.any, "async ownership wildcard must be true")
                        }
                        AsyncOwnershipArgument::Json(value) => {
                            ensure!(
                                (1..=32).contains(&value.json.len()),
                                "async ownership JSON constraints exceed bounds"
                            );
                            for (pointer, constraint) in &value.json {
                                super::super::validate_pointer(pointer, true)?;
                                ensure!(
                                    !pointer.split('/').any(|part| part == "*"),
                                    "async ownership JSON pointers must be concrete"
                                );
                                match constraint {
                                    AsyncOwnershipJsonValue::Literal(value) => ensure!(
                                        value.literal.is_string()
                                            || value.literal.is_number()
                                            || value.literal.is_boolean()
                                            || value.literal.is_null(),
                                        "async ownership JSON literal must be scalar"
                                    ),
                                    AsyncOwnershipJsonValue::Identity(value) => {
                                        identity(value, origin)?;
                                        bound = true;
                                    }
                                }
                            }
                        }
                    }
                }
                ensure!(
                    bound,
                    "async ownership Redis selector requires an identity binding"
                );
                if *script_exists_prelude {
                    ensure!(
                        operation == "EVALSHA"
                            && matches!(arguments.first(), Some(AsyncOwnershipArgument::Literal(sha)) if sha.len()==40 && sha.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
                        "SCRIPT prelude requires an identity-bound EVALSHA with a literal lowercase SHA-1"
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) use validate as validate_async_ownership;
