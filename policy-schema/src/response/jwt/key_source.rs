//! Response verification inputs; recorded database keys never enter request execution.
use super::*;
use anyhow::Context;
use std::path::PathBuf;
use traffic_jwt::key::SigningKeySource;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseJwtKeySource {
    TargetEnv {
        name: String,
    },
    TargetFile {
        path: PathBuf,
        field: String,
    },
    RecordedMysql {
        host: String,
        port: u16,
        database: String,
        sql: String,
        #[serde(default)]
        params: Vec<serde_json::Value>,
        column: String,
        json_pointer: String,
        kid_pointer: String,
        algorithm_pointer: String,
        kid: String,
    },
}

impl ResponseJwtKeySource {
    pub fn startup(&self) -> Option<SigningKeySource> {
        match self {
            Self::TargetEnv { name } => Some(SigningKeySource::TargetEnv { name: name.clone() }),
            Self::TargetFile { path, field } => Some(SigningKeySource::TargetFile {
                path: path.clone(),
                field: field.clone(),
            }),
            Self::RecordedMysql { .. } => None,
        }
    }

    pub fn validate(&self, algorithm: ResponseJwtAlgorithm) -> Result<()> {
        if let Some(source) = self.startup() {
            return traffic_jwt::key::validate_source(&source);
        }
        let Self::RecordedMysql {
            host,
            port,
            database,
            sql,
            params,
            column,
            json_pointer,
            kid_pointer,
            algorithm_pointer,
            kid,
        } = self
        else {
            unreachable!()
        };
        ensure!(
            algorithm == ResponseJwtAlgorithm::RS256,
            "recorded_mysql is a public-key source for RS256 responses only"
        );
        for (value, field) in [
            (host, "host"),
            (database, "database"),
            (column, "column"),
            (kid, "kid"),
        ] {
            validate_audit_text(value, field, 256)?;
        }
        ensure!(
            *port > 0 && sql.len() <= 8192 && params.len() <= 64,
            "invalid recorded_mysql selector bounds"
        );
        for pointer in [json_pointer, kid_pointer, algorithm_pointer] {
            validate_json_pointer(pointer)?;
        }
        let tokens = Self::selector_tokens(sql, params)?;
        ensure!(
            tokens.first().is_some_and(|t| t.is("select")) && !tokens.iter().any(|t| t.is(";")),
            "recorded_mysql key selector must be a SELECT"
        );
        Ok(())
    }

    pub fn selector_tokens(
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<traffic_protocol_mysql_sql::sql::Token>> {
        let params = params
            .iter()
            .map(|value| {
                let kind = match value {
                    serde_json::Value::Null => "null",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
                    _ => anyhow::bail!("recorded_mysql params must be strings, integers or null"),
                };
                Ok(traffic_protocol_mysql_sql::binding::MysqlValue {
                    kind: kind.into(),
                    value: Some(value.clone()),
                    raw: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        traffic_protocol_mysql_sql::binding::materialize(sql, &params)
            .context("recorded_mysql SQL or parameter count is invalid")
    }
}
