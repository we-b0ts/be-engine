//! Native SQL literal, parameter and physical-column locations for shared rules.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};

use crate::{model::MysqlValue, sql::Token};

pub struct RequestMessage {
    pub command: String,
    pub sql: Option<String>,
    pub params: Option<Vec<MysqlValue>>,
    pub database: Option<String>,
    pub username: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestLocation {
    Request,
    Parameter {
        index: usize,
    },
    Literal {
        index: usize,
    },
    Field {
        database: Option<String>,
        table: String,
        column: String,
    },
}

impl ProtocolMessage for RequestMessage {
    fn project(&self) -> Result<ProjectedMessage> {
        let mut values = BTreeMap::new();
        let sql = self
            .sql
            .as_deref()
            .map(|sql| {
                if matches!(
                    self.command.as_str(),
                    "COM_QUERY" | "COM_STMT_EXECUTE" | "COM_STMT_PREPARE"
                ) {
                    project_sql(sql, &mut values)
                } else {
                    Ok(Value::String(sql.into()))
                }
            })
            .transpose()?;
        let parameters = self
            .params
            .as_ref()
            .map(|params| {
                params
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let projected = project_value(value)?;
                        values.insert(parameter_location(index), projected);
                        Ok(value.kind.clone())
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        Ok(ProjectedMessage {
            structure: json!({"command":self.command, "sql":sql, "parameters":parameters,
                "database":self.database, "username":self.username}),
            values,
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        match serde_json::from_value::<RequestLocation>(selector.clone())? {
            RequestLocation::Request => Ok(self.project()?.values.into_keys().collect()),
            RequestLocation::Parameter { index } => {
                ensure!(
                    self.params
                        .as_ref()
                        .is_some_and(|params| index < params.len()),
                    "MySQL parameter selector is out of range"
                );
                Ok(vec![parameter_location(index)])
            }
            RequestLocation::Literal { index } => {
                let count = self
                    .sql
                    .as_deref()
                    .and_then(crate::sql::tokens)
                    .map_or(0, |tokens| {
                        tokens.iter().filter(|token| token.is_value()).count()
                    });
                ensure!(index < count, "MySQL literal selector is out of range");
                Ok(vec![literal_location(index)])
            }
            RequestLocation::Field {
                database,
                table,
                column,
            } => {
                let Some(tokens) = self.sql.as_deref().and_then(crate::sql::tokens_shared) else {
                    return Ok(Vec::new());
                };
                let Some(analysis) =
                    crate::sql::field_bindings::analyze(&tokens, self.database.as_deref())
                else {
                    return Ok(Vec::new());
                };
                let mut literals = 0;
                let mut parameters = 0;
                let mut locations = Vec::new();
                for (index, token) in tokens.iter().enumerate() {
                    let location = match token {
                        Token::Placeholder => {
                            let location = self
                                .params
                                .as_ref()
                                .filter(|params| parameters < params.len())
                                .map(|_| parameter_location(parameters));
                            parameters += 1;
                            location
                        }
                        token if token.is_value() => {
                            let location = literal_location(literals);
                            literals += 1;
                            Some(location)
                        }
                        _ => None,
                    };
                    if let Some(location) = location
                        && analysis.at_token(index).is_some_and(|field| {
                            field.table == table
                                && field.column == column
                                && database.as_ref().is_none_or(|database| {
                                    field.database.as_ref() == Some(database)
                                })
                        })
                    {
                        locations.push(location);
                    }
                }
                Ok(locations)
            }
        }
    }

    fn evidence(&self, query: &Value) -> Result<Value> {
        let projection = self.project()?;
        let values = self
            .locate(query)?
            .into_iter()
            .map(|location| {
                let capture = traffic_model::capture::capture_body(
                    &projection.values[&location].bytes,
                    usize::MAX,
                );
                json!({"location":location, "capture":capture})
            })
            .collect::<Vec<_>>();
        Ok(json!({"command":self.command, "database":self.database, "values":values}))
    }
}

fn project_sql(sql: &str, values: &mut BTreeMap<String, ProjectedValue>) -> Result<Value> {
    let Some(tokens) = crate::sql::tokens_shared(sql) else {
        return Ok(json!({"opaque_sql":sql}));
    };
    let mut literal = 0;
    let mut structure = Vec::new();
    for token in tokens.iter() {
        let shape = match token {
            Token::Bytes(bytes) => {
                let location = literal_location(literal);
                literal += 1;
                if let Ok(text) = std::str::from_utf8(bytes) {
                    values.insert(
                        location.clone(),
                        ProjectedValue::bytes(Bytes::copy_from_slice(text.as_bytes())),
                    );
                    json!({"text_literal":location})
                } else {
                    values.insert(
                        location.clone(),
                        ProjectedValue::bytes(Bytes::copy_from_slice(bytes)),
                    );
                    json!({"binary_literal":location})
                }
            }
            Token::Number(number) => {
                let location = literal_location(literal);
                literal += 1;
                values.insert(
                    location.clone(),
                    ProjectedValue::json(Bytes::copy_from_slice(number.as_bytes())),
                );
                json!({"numeric_literal":location})
            }
            Token::Null => {
                let location = literal_location(literal);
                literal += 1;
                values.insert(
                    location.clone(),
                    ProjectedValue::json(Bytes::from_static(b"null")),
                );
                json!({"null_literal":location})
            }
            Token::Word(word) => json!({"word":word}),
            Token::Identifier(identifier) => json!({"identifier":identifier}),
            Token::Placeholder => json!({"parameter":true}),
            Token::Symbol(symbol) => json!({"symbol":symbol}),
        };
        structure.push(shape);
    }
    Ok(Value::Array(structure))
}

fn parameter_location(index: usize) -> String {
    format!("/params/{index}")
}
fn literal_location(index: usize) -> String {
    format!("/literals/{index}")
}

pub(crate) fn project_value(value: &MysqlValue) -> Result<ProjectedValue> {
    ensure!(
        value.raw.as_ref().is_none_or(|raw| !raw.truncated),
        "truncated MySQL value"
    );
    if value.raw.is_some() {
        return Ok(ProjectedValue::bytes(crate::values::mysql_value_bytes(
            value,
        )?));
    }
    if matches!(value.kind.as_str(), "string" | "json")
        && let Some(Value::String(text)) = &value.value
    {
        return Ok(ProjectedValue::bytes(Bytes::copy_from_slice(
            text.as_bytes(),
        )));
    }
    Ok(ProjectedValue::json(serde_json::to_vec(
        value.value.as_ref().unwrap_or(&Value::Null),
    )?))
}
