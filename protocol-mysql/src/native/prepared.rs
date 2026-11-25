//! Connection-local prepared metadata and exact text-wire equivalents.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use traffic_protocol::{
    connection::{ConnectionIo, RequestHost, RequestSession},
    message::{ProjectedMessage, ProtocolMessage},
};

use super::response::ResponseMessage;
use crate::{
    MysqlPacket,
    message::{RequestMessage, project_sql_tokens},
    model::{MysqlColumn, PreparedStatement},
    prepare::StatementMetadata,
    sql::Token,
};

pub(super) struct Statements {
    next_id: u32,
    statements: HashMap<u32, Statement>,
}

impl Default for Statements {
    fn default() -> Self {
        Self {
            next_id: 1,
            statements: HashMap::new(),
        }
    }
}

struct Statement {
    bind: PreparedStatement,
    columns: Arc<[MysqlColumn]>,
    database: Option<String>,
}

impl Statements {
    pub(super) async fn prepare(
        &mut self,
        io: &mut dyn ConnectionIo,
        host: &dyn RequestHost,
        session: &RequestSession,
        status: u16,
        request: RequestMessage,
    ) -> Result<bool> {
        let sql = request
            .sql
            .as_deref()
            .context("MySQL prepared SQL is absent")?;
        let tokens =
            crate::sql::bounds::statement_shared(sql).context("unsupported MySQL prepared SQL")?;
        ensure!(
            tokens.first().is_some_and(|token| {
                ["select", "insert", "update", "delete", "replace"]
                    .iter()
                    .any(|verb| token.is(verb))
            }),
            "unsupported MySQL prepared statement class"
        );
        let Some(response) = host.statement_metadata(&request, session).await? else {
            return Ok(false);
        };
        let response = response
            .as_any()
            .and_then(|message| message.downcast_ref::<ResponseMessage>())
            .context("MySQL prepared statement has no native Source metadata")?;
        if !matches!(response.response.status.as_str(), "ok" | "resultset")
            || response
                .response
                .server_status
                .is_none_or(|status| status & 8 != 0)
        {
            return Ok(false);
        }
        let count = tokens
            .iter()
            .filter(|token| **token == Token::Placeholder)
            .count();
        ensure!(
            response.response.columns.len() <= u16::MAX as usize && count <= u16::MAX as usize,
            "MySQL prepared metadata exceeds protocol limits"
        );
        ensure!(
            self.statements.len() < 1024,
            "MySQL prepared statement capacity exceeded"
        );
        let metadata = StatementMetadata::new(count, response.response.columns.clone());
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .context("MySQL prepared statement identity exhausted")?;
        let mut output = crate::output::prepare(id, &metadata, status);
        traffic_replay::output::deliver(io, &mut output, None).await?;
        self.statements.insert(
            id,
            Statement {
                bind: PreparedStatement {
                    sql: sql.into(),
                    param_count: count,
                    last_param_types: Vec::new(),
                },
                columns: metadata.columns.clone().into(),
                database: request.database,
            },
        );
        Ok(true)
    }

    pub(super) fn execute(
        &mut self,
        packet: &MysqlPacket,
        database: Option<String>,
        username: Option<String>,
    ) -> Result<(PreparedExecution, Arc<[MysqlColumn]>)> {
        let id = crate::values::read_u32_le(&packet.payload, 1)
            .context("MySQL prepared execution is missing its statement identity")?;
        let statement = self
            .statements
            .get_mut(&id)
            .context("MySQL prepared execution has unknown statement identity")?;
        ensure!(
            statement.database == database,
            "MySQL prepared statement database changed after prepare"
        );
        let parsed = crate::prepared::parse_stmt_execute_strict(packet, &statement.bind)?;
        let params = parsed
            .params
            .context("MySQL prepared parameters are missing")?;
        let types = parsed
            .param_types
            .context("MySQL prepared parameter types are missing")?;
        let materialized = crate::sql_match::materialize(&statement.bind.sql, &params)
            .context("MySQL prepared parameters cannot bind the proven statement template")?;
        statement.bind.last_param_types = types;
        let request = RequestMessage {
            command: "COM_STMT_EXECUTE".into(),
            sql: Some(statement.bind.sql.clone()),
            params: Some(params),
            database,
            username,
        };
        let text = TextExecution {
            database: request.database.clone(),
            username: request.username.clone(),
            tokens: materialized,
        };
        Ok((
            PreparedExecution { request, text },
            statement.columns.clone(),
        ))
    }

    pub(super) fn close(&mut self, packet: &MysqlPacket) -> Result<()> {
        ensure!(
            packet.payload.len() == 5,
            "invalid MySQL prepared close packet"
        );
        let id = crate::values::read_u32_le(&packet.payload, 1)
            .context("MySQL prepared close is missing its statement identity")?;
        ensure!(
            self.statements.remove(&id).is_some(),
            "MySQL prepared close has unknown statement identity"
        );
        Ok(())
    }
}

pub(super) struct PreparedExecution {
    pub request: RequestMessage,
    text: TextExecution,
}

impl ProtocolMessage for PreparedExecution {
    fn command_name(&self) -> Option<&str> {
        self.request.command_name()
    }
    fn exact_request_alternative(&self) -> Option<&dyn ProtocolMessage> {
        Some(&self.text)
    }
    fn project(&self) -> Result<ProjectedMessage> {
        self.request.project()
    }
    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        self.request.locate(selector)
    }
    fn evidence(&self, selector: &Value) -> Result<Value> {
        self.request.evidence(selector)
    }
}

struct TextExecution {
    database: Option<String>,
    username: Option<String>,
    tokens: Vec<Token>,
}

impl ProtocolMessage for TextExecution {
    fn project(&self) -> Result<ProjectedMessage> {
        let mut values = BTreeMap::new();
        let sql = project_sql_tokens(&self.tokens, &mut values);
        Ok(ProjectedMessage {
            structure: json!({"command":"COM_QUERY", "sql":sql, "parameters":null, "database":self.database, "username":self.username}),
            values,
        })
    }

    fn locate(&self, selector: &Value) -> Result<Vec<String>> {
        ensure!(
            selector["kind"] == "request",
            "bound MySQL text form supports whole-request comparison"
        );
        Ok(self.project()?.values.into_keys().collect())
    }

    fn evidence(&self, selector: &Value) -> Result<Value> {
        let projection = self.project()?;
        let values = self
            .locate(selector)?
            .into_iter()
            .map(|path| {
                let capture = traffic_model::capture::capture_body(
                    &projection.values[&path].bytes,
                    usize::MAX,
                );
                json!({"location":path, "capture":capture})
            })
            .collect::<Vec<_>>();
        Ok(json!({"command":"COM_QUERY", "database":self.database, "values":values}))
    }
}
