use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs::OpenOptions;

use super::summary::should_append_case_dependency;
use crate::recorder::{CaseContext, Recorder, RecorderEvent};

pub(super) async fn ensure_case_dependency_file(dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("failed to create case recording dir {}", dir.display()))?;
    let path = dir.join("dependencies.jsonl");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("failed to create dependencies file {}", path.display()))?;
    Ok(())
}

impl Recorder {
    pub async fn append_case_dependency(
        &self,
        case: &CaseContext,
        event: &RecorderEvent,
        matched_by: &str,
    ) -> Result<()> {
        if !should_append_case_dependency(event) {
            return Ok(());
        }
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        if self.finalized_cases.lock().await.contains(&case.id) {
            return Ok(());
        }
        let dir = self.case_staging_dir(case);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("failed to create case recording dir {}", dir.display()))?;
        let path = dir.join(case_dependency_filename(event));
        let line = dependency_line(event, "case_dependency_matched_by", matched_by)?;
        self.dependency_files
            .lock()
            .await
            .append(&path, &line)
            .await
    }

    pub async fn append_bootstrap_dependency(
        &self,
        event: &RecorderEvent,
        matched_by: &str,
    ) -> Result<()> {
        if !should_append_case_dependency(event) {
            return Ok(());
        }
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        tokio::fs::create_dir_all(&*self.run_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create recording run dir {}",
                    self.run_dir.display()
                )
            })?;
        let path = self.run_dir.join(bootstrap_dependency_filename(event));
        let line = dependency_line(event, "bootstrap_dependency_matched_by", matched_by)?;
        self.dependency_files
            .lock()
            .await
            .append(&path, &line)
            .await
    }

    pub(crate) async fn case_dependency_safety_issue(
        &self,
        case: &CaseContext,
    ) -> Result<Option<String>> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        let path = self.case_staging_dir(case).join("dependencies.jsonl");
        self.dependency_files
            .lock()
            .await
            .flush_and_remove(&path)
            .await?;
        let raw = match tokio::fs::read_to_string(&path).await {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to inspect case dependencies {}", path.display())
                });
            }
        };
        for (index, line) in raw.lines().enumerate() {
            let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
                format!(
                    "invalid dependency JSON at {} line {}",
                    path.display(),
                    index + 1
                )
            })?;
            let event_type = value
                .get("event_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if matches!(
                event_type,
                "redis_connection"
                    | "redis_exchange"
                    | "memcached_connection"
                    | "memcached_exchange"
                    | "kafka_connection"
                    | "kafka_produce"
                    | "kafka_fetch"
                    | "kafka_delivery"
            ) && value
                .get("replay_safe")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            {
                let command = value
                    .get("command")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                return Ok(Some(format!(
                    "{event_type} command {command} contains incomplete or unsupported replay evidence"
                )));
            }
            if event_type == "proxy_error"
                && matches!(
                    value.get("protocol").and_then(serde_json::Value::as_str),
                    Some("redis" | "memcached" | "kafka")
                )
            {
                return Ok(Some(format!(
                    "dependency proxy error: {}",
                    value
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown dependency proxy error")
                )));
            }
        }
        Ok(None)
    }

    pub(super) async fn flush_case_dependency_files(&self, dir: &Path) -> Result<()> {
        self.dependency_files
            .lock()
            .await
            .flush_and_remove_under(dir)
            .await
    }

    pub(super) async fn flush_bootstrap_dependency_files(&self) -> Result<()> {
        let semantic = self.run_dir.join("bootstrap-dependencies.jsonl");
        let debug = self.run_dir.join("bootstrap-dependencies-debug.jsonl");
        let mut files = self.dependency_files.lock().await;
        files.flush_and_remove(&semantic).await?;
        files.flush_and_remove(&debug).await
    }

    pub(super) async fn flush_all_dependency_files(&self) -> Result<()> {
        self.dependency_files.lock().await.flush_all().await
    }
}

fn dependency_line(
    event: &RecorderEvent,
    matched_by_field: &str,
    matched_by: &str,
) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(event).context("failed to serialize dependency event")?;
    compact_process_info(&mut value);
    if let serde_json::Value::Object(object) = &mut value {
        object.insert(
            matched_by_field.to_string(),
            serde_json::Value::String(matched_by.to_string()),
        );
    }
    let mut line = serde_json::to_vec(&value).context("failed to serialize dependency event")?;
    line.push(b'\n');
    Ok(line)
}

fn case_dependency_filename(event: &RecorderEvent) -> &'static str {
    if is_debug_event(event) {
        "dependencies-debug.jsonl"
    } else {
        "dependencies.jsonl"
    }
}

fn bootstrap_dependency_filename(event: &RecorderEvent) -> &'static str {
    if is_debug_event(event) {
        "bootstrap-dependencies-debug.jsonl"
    } else {
        "bootstrap-dependencies.jsonl"
    }
}

fn is_debug_event(event: &RecorderEvent) -> bool {
    matches!(
        event,
        RecorderEvent::MysqlQuery(_)
            | RecorderEvent::MysqlResponse(_)
            | RecorderEvent::MysqlPacket(_)
    ) || matches!(event, RecorderEvent::RedisExchange(exchange) if exchange.command == "QUIT")
}

fn compact_process_info(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(process) = object.get_mut("client_process")
                && let Some(pid) = process.get("pid").and_then(serde_json::Value::as_u64)
            {
                *process = serde_json::Value::Number(pid.into());
            }
            for child in object.values_mut() {
                compact_process_info(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                compact_process_info(child);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::DependencyExchangeOutcome;
    use crate::recorder::{
        MysqlExchangeEvent, MysqlExchangeResponse, MysqlQueryEvent, RedisExchangeEvent,
        capture_body,
    };

    #[tokio::test]
    async fn mysql_maintenance_requests_are_kept_in_debug_only() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let connection_id = Uuid::new_v4();

        let maintenance = [
            (1, "COM_PING", None),
            (
                2,
                "COM_QUERY",
                Some("SHOW FULL TABLES FROM `` LIKE 'PROBABLYNOT'"),
            ),
            (3, "COM_QUERY", Some("SELECT 1;")),
        ];
        for (sequence, command, sql) in maintenance {
            recorder
                .append_case_dependency(
                    &case,
                    &RecorderEvent::MysqlQuery(mysql_query(connection_id, sequence, command, sql)),
                    "process",
                )
                .await
                .unwrap();
            let mut exchange = mysql_exchange(connection_id, sequence, command, sql);
            if sequence == 2 {
                exchange.response.status = "incomplete".to_string();
                exchange
                    .parse_warnings
                    .push("no server response packets were captured".to_string());
            }
            recorder
                .append_case_dependency(&case, &RecorderEvent::MysqlExchange(exchange), "process")
                .await
                .unwrap();
        }
        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    connection_id,
                    4,
                    "COM_QUERY",
                    Some("SELECT 2"),
                )),
                "process",
            )
            .await
            .unwrap();

        let case_dir = recorder.case_staging_dir(&case);
        recorder
            .flush_case_dependency_files(&case_dir)
            .await
            .unwrap();

        let semantic = tokio::fs::read_to_string(case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert_eq!(semantic.lines().count(), 1);
        assert!(semantic.contains("SELECT 2"));
        assert!(!semantic.contains("COM_PING"));
        assert!(!semantic.contains("PROBABLYNOT"));
        assert!(!semantic.contains("SELECT 1"));

        let debug = tokio::fs::read_to_string(case_dir.join("dependencies-debug.jsonl"))
            .await
            .unwrap();
        assert!(debug.contains("COM_PING"));
        assert!(debug.contains("PROBABLYNOT"));
        assert!(debug.contains("SELECT 1"));

        super::super::summary::write_case_dependency_summary(&case_dir)
            .await
            .unwrap();
        let summary = tokio::fs::read_to_string(case_dir.join("dependencies-summary.json"))
            .await
            .unwrap();
        assert!(!summary.contains("COM_PING"));
        assert!(!summary.contains("PROBABLYNOT"));
        assert!(!summary.contains("SELECT 1"));

        for (sequence, command, sql) in maintenance {
            recorder
                .append_bootstrap_dependency(
                    &RecorderEvent::MysqlQuery(mysql_query(connection_id, sequence, command, sql)),
                    "bootstrap_window",
                )
                .await
                .unwrap();
            recorder
                .append_bootstrap_dependency(
                    &RecorderEvent::MysqlExchange(mysql_exchange(
                        connection_id,
                        sequence,
                        command,
                        sql,
                    )),
                    "bootstrap_window",
                )
                .await
                .unwrap();
        }
        recorder
            .append_bootstrap_dependency(
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    connection_id,
                    4,
                    "COM_QUERY",
                    Some("SELECT 2"),
                )),
                "bootstrap_window",
            )
            .await
            .unwrap();
        recorder.flush_bootstrap_dependency_files().await.unwrap();

        let bootstrap_semantic =
            tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies.jsonl"))
                .await
                .unwrap();
        assert_eq!(bootstrap_semantic.lines().count(), 1);
        assert!(bootstrap_semantic.contains("SELECT 2"));
        assert!(!bootstrap_semantic.contains("COM_PING"));
        assert!(!bootstrap_semantic.contains("PROBABLYNOT"));
        assert!(!bootstrap_semantic.contains("SELECT 1"));

        let bootstrap_debug =
            tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies-debug.jsonl"))
                .await
                .unwrap();
        assert!(bootstrap_debug.contains("COM_PING"));
        assert!(bootstrap_debug.contains("PROBABLYNOT"));
        assert!(bootstrap_debug.contains("SELECT 1"));
    }

    #[tokio::test]
    async fn redis_quit_is_kept_in_debug_only() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let connection_id = Uuid::new_v4();
        let quit = RecorderEvent::RedisExchange(redis_exchange(
            connection_id,
            1,
            "QUIT",
            DependencyExchangeOutcome::NoResponse,
        ));
        let get = RecorderEvent::RedisExchange(redis_exchange(
            connection_id,
            2,
            "GET",
            DependencyExchangeOutcome::Response,
        ));

        for event in [&quit, &get] {
            recorder
                .append_case_dependency(&case, event, "process")
                .await
                .unwrap();
        }
        let case_dir = recorder.case_staging_dir(&case);
        recorder
            .flush_case_dependency_files(&case_dir)
            .await
            .unwrap();

        let semantic = tokio::fs::read_to_string(case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert!(semantic.contains("\"command\":\"GET\""));
        assert!(!semantic.contains("\"command\":\"QUIT\""));
        let debug = tokio::fs::read_to_string(case_dir.join("dependencies-debug.jsonl"))
            .await
            .unwrap();
        assert!(debug.contains("\"command\":\"QUIT\""));
        assert!(!debug.contains("\"command\":\"GET\""));

        super::super::summary::write_case_dependency_summary(&case_dir)
            .await
            .unwrap();
        let summary = tokio::fs::read_to_string(case_dir.join("dependencies-summary.json"))
            .await
            .unwrap();
        assert!(summary.contains("\"GET\""));
        assert!(!summary.contains("\"QUIT\""));

        for event in [&quit, &get] {
            recorder
                .append_bootstrap_dependency(event, "bootstrap_window")
                .await
                .unwrap();
        }
        recorder.flush_bootstrap_dependency_files().await.unwrap();

        let semantic =
            tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies.jsonl"))
                .await
                .unwrap();
        assert!(semantic.contains("\"command\":\"GET\""));
        assert!(!semantic.contains("\"command\":\"QUIT\""));
        let debug =
            tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies-debug.jsonl"))
                .await
                .unwrap();
        assert!(debug.contains("\"command\":\"QUIT\""));
        assert!(!debug.contains("\"command\":\"GET\""));
    }

    fn mysql_query(
        connection_id: Uuid,
        sequence: u64,
        command: &str,
        query: Option<&str>,
    ) -> MysqlQueryEvent {
        MysqlQueryEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence,
            timestamp: Utc::now(),
            client_addr: None,
            client_process: None,
            command: command.to_string(),
            query: query.map(ToOwned::to_owned),
            payload_len: query.map_or(1, str::len),
        }
    }

    fn mysql_exchange(
        connection_id: Uuid,
        query_sequence: u64,
        command: &str,
        sql: Option<&str>,
    ) -> MysqlExchangeEvent {
        MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id,
            query_sequence,
            timestamp: Utc::now(),
            client_addr: None,
            client_process: None,
            route_name: None,
            target_host: Some("mysql.internal".to_string()),
            target_port: Some(3306),
            target_addr: Some("mysql.internal:3306".to_string()),
            upstream_addr: Some("10.0.0.1:3306".to_string()),
            username: Some("root".to_string()),
            database: Some("appdb".to_string()),
            command: command.to_string(),
            sql: sql.map(ToOwned::to_owned),
            statement_id: None,
            params: None,
            response: MysqlExchangeResponse {
                status: "ok".to_string(),
                error_code: None,
                error_message: None,
                affected_rows: Some(0),
                last_insert_id: Some(0),
                columns: Vec::new(),
                rows: Vec::new(),
                row_count: 0,
                rows_truncated: false,
            },
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 1,
            parse_warnings: Vec::new(),
        }
    }

    fn redis_exchange(
        connection_id: Uuid,
        sequence: u64,
        command: &str,
        outcome: DependencyExchangeOutcome,
    ) -> RedisExchangeEvent {
        RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id,
            sequence,
            timestamp: Utc::now(),
            client_addr: None,
            client_process: None,
            target_host: "redis.internal".to_string(),
            target_port: 6379,
            target_addr: "redis.internal:6379".to_string(),
            upstream_addr: "10.0.0.2:6379".to_string(),
            resp_version: 2,
            database: 0,
            username: None,
            command: command.to_string(),
            args: Vec::new(),
            response_kind: if command == "GET" {
                "bulk_string".to_string()
            } else {
                "other".to_string()
            },
            response: capture_body(if command == "GET" { b"$-1\r\n" } else { b"" }, 1024),
            session_setup: false,
            outcome,
            duration_ms: 0,
            replay_safe: true,
            parse_warnings: Vec::new(),
        }
    }
}
