use super::*;
use crate::policy::native::Literal;
use crate::policy::{Database, Endpoint, Protocol, Resource, SourceScalar};

pub(super) fn convert(
    value: &super::super::super::ApiTriggerSource,
    proof: &Proof,
) -> Result<Proven<n::ApiOrigin>> {
    let request_body = value
        .request_body_json
        .iter()
        .map(|(key, value)| Ok((key.clone(), scalar(value)?)))
        .collect::<Result<_>>()?;
    let capture = value
        .capture
        .iter()
        .map(|(key, value)| {
            let row_match = value
                .row_match
                .iter()
                .map(|(column, value)| Ok((column.clone(), literal(value)?)))
                .collect::<Result<_>>()?;
            Ok((
                key.clone(),
                Proven {
                    contract: n::OriginCapture {
                        resource: Resource {
                            protocol: Protocol::Mysql,
                            endpoint: Endpoint {
                                host: value.target_host.clone(),
                                port: value.target_port,
                            },
                            database: Some(Database::Name(value.database.clone())),
                            username: Some(value.username.clone()),
                        },
                        operation: n::OriginOperation::Insert,
                        tables: value.tables.clone(),
                        table_patterns: value.table_patterns.clone(),
                        row_match,
                        column: value.column.clone(),
                    },
                    proof: proof.clone(),
                },
            ))
        })
        .collect::<Result<_>>()?;
    Ok(Proven {
        contract: n::ApiOrigin {
            api: format!("{} {}", value.method, value.path),
            request_body,
            capture,
        },
        proof: proof.clone(),
    })
}
fn scalar(value: &serde_json::Value) -> Result<SourceScalar> {
    Ok(match value {
        serde_json::Value::Bool(value) => SourceScalar::Bool(*value),
        serde_json::Value::Number(value) => SourceScalar::Number(value.clone()),
        serde_json::Value::String(value) => SourceScalar::String(value.clone()),
        _ => anyhow::bail!("Source origin predicate is not a typed scalar"),
    })
}
fn literal(value: &serde_json::Value) -> Result<Literal> {
    Ok(match value {
        serde_json::Value::String(value) => Literal::String(value.clone()),
        serde_json::Value::Number(value) => Literal::Integer(
            value
                .as_i64()
                .context("Source origin row predicate requires an exact integer")?,
        ),
        _ => anyhow::bail!("Source origin row predicate must be an integer or string"),
    })
}
