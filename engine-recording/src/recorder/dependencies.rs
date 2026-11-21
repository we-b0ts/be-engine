use std::path::Path;

use anyhow::{Context, Result};

use crate::recorder::{CaseContext, Recorder};
use traffic_protocol::capture::CaptureEvidence;

pub(super) async fn ensure_case_dependency_file(dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("failed to create case recording dir {}", dir.display()))?;
    anyhow::ensure!(
        dir.join("dependency-scope.json").is_file(),
        "case has no immutable central dependency scope"
    );
    Ok(())
}

impl Recorder {
    pub async fn append_case_dependency(
        &self,
        case: &CaseContext,
        event: &impl CaptureEvidence,
        matched_by: &str,
    ) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        self.writer
            .append_case(
                case.clone(),
                traffic_recorder::CapturedEvent::capture(event)?,
                matched_by,
            )
            .await
    }

    pub async fn append_global_dependency(
        &self,
        event: &impl CaptureEvidence,
        reason: &str,
        phase: &str,
        matched_by: &str,
    ) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        self.writer
            .append_global(
                traffic_recorder::CapturedEvent::capture(event)?,
                reason,
                phase,
                matched_by,
            )
            .await
    }

    pub async fn case_dependency_safety_issue(&self, case: &CaseContext) -> Result<Option<String>> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
        let path = self.case_staging_dir(case).join("dependencies.jsonl");
        self.writer
            .flush_case(path.parent().expect("case dependency has a parent"))
            .await?;
        let raw = match crate::dependency_index::scoped::read_bytes(&path)
            .and_then(|bytes| String::from_utf8(bytes).map_err(anyhow::Error::from))
        {
            Ok(raw) => raw,
            Err(err)
                if err
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|err| err.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
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
            if let Some(outcome) = value.get("outcome") {
                let validation =
                    serde_json::from_value::<crate::DependencyExchangeOutcome>(outcome.clone())
                        .map_err(anyhow::Error::from)
                        .and_then(crate::DependencyExchangeOutcome::validate);
                if let Err(error) = validation {
                    return Ok(Some(format!(
                        "{event_type} has invalid transport termination evidence: {error}"
                    )));
                }
            }
            if let Some(issue) = self.source_preparation.safety_issue(&value) {
                return Ok(Some(issue));
            }
        }
        Ok(None)
    }

    pub async fn flush_case_dependency_files(&self, dir: &Path) -> Result<()> {
        self.writer.flush_case(dir).await
    }

    pub async fn flush_global_dependency_files(&self) -> Result<()> {
        self.writer.flush_global().await
    }

    pub async fn flush_all_dependency_files(&self) -> Result<()> {
        self.writer.flush_all().await
    }
}

#[cfg(test)]
mod tests {
    use crate::RecorderEvent;
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::DependencyExchangeOutcome;
    use crate::protocols::recording::events::{
        MysqlExchangeEvent, MysqlExchangeResponse, MysqlQueryEvent, RedisExchangeEvent,
    };
    use crate::recorder::capture_body;

    #[tokio::test]
    async fn mysql_peer_failure_can_publish_while_interrupted_capture_cannot() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        for (status, warning, peer_end, unsafe_capture) in [
            ("server_terminated", None, true, false),
            (
                "server_terminated",
                Some("unsupported pending batch"),
                true,
                true,
            ),
            (
                "incomplete",
                Some("engine cleanup interrupted capture"),
                false,
                true,
            ),
            ("error", None, false, false),
        ] {
            let case = CaseContext {
                id: Uuid::new_v4(),
                rule_name: "api".into(),
                uri_group: None,
            };
            let mut exchange = mysql_exchange(Uuid::new_v4(), 1, "COM_QUERY", Some("SELECT value"));
            exchange.response.status = status.into();
            if peer_end {
                exchange.outcome =
                    DependencyExchangeOutcome::Terminated(crate::DependencyTermination {
                        side: crate::TerminationSide::Server,
                        kind: crate::TerminationKind::Reset,
                        scope: crate::TerminationScope::Connection,
                    });
            }
            if let Some(warning) = warning {
                exchange.parse_warnings.push(warning.into());
            }
            recorder
                .append_case_dependency(
                    &case,
                    &RecorderEvent::MysqlExchange(exchange),
                    "active_window",
                )
                .await
                .unwrap();
            assert_eq!(
                recorder
                    .case_dependency_safety_issue(&case)
                    .await
                    .unwrap()
                    .is_some(),
                unsafe_capture
            );
        }
    }

    #[tokio::test]
    async fn mysql_probe_facts_are_preserved_without_business_consumption_slots() {
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
            (4, "COM_QUERY", Some("SELECT 2")),
        ];
        for (sequence, command, sql) in maintenance {
            recorder
                .append_case_dependency(
                    &case,
                    &RecorderEvent::MysqlQuery(mysql_query(connection_id, sequence, command, sql)),
                    "active_window",
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
                .append_case_dependency(
                    &case,
                    &RecorderEvent::MysqlExchange(exchange),
                    "active_window",
                )
                .await
                .unwrap();
        }
        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    connection_id,
                    5,
                    "COM_QUERY",
                    Some("SELECT 3"),
                )),
                "active_window",
            )
            .await
            .unwrap();

        let case_dir = recorder.case_staging_dir(&case);
        recorder
            .flush_case_dependency_files(&case_dir)
            .await
            .unwrap();

        let semantic =
            crate::recorder::test_io::read_to_string(case_dir.join("dependencies.jsonl"))
                .await
                .unwrap();
        assert_eq!(semantic.lines().count(), 5);
        assert!(semantic.contains("SELECT 3"));
        assert!(semantic.contains("COM_PING"));
        assert!(semantic.contains("PROBABLYNOT"));
        assert!(semantic.contains("SELECT 1"));
        assert!(semantic.contains("SELECT 2"));

        let debug =
            crate::recorder::test_io::read_to_string(case_dir.join("dependencies-debug.jsonl"))
                .await
                .unwrap();
        assert!(debug.contains("COM_PING"));
        assert!(debug.contains("PROBABLYNOT"));
        assert!(debug.contains("SELECT 1"));
        assert!(debug.contains("SELECT 2"));

        super::super::summary::write_case_dependency_summary(&case_dir, recorder.evidence.clone())
            .await
            .unwrap();
        let summary =
            crate::recorder::test_io::read_to_string(case_dir.join("dependencies-summary.json"))
                .await
                .unwrap();
        assert!(!summary.contains("COM_PING"));
        assert!(!summary.contains("PROBABLYNOT"));
        assert!(!summary.contains("SELECT 1"));
        assert!(!summary.contains("SELECT 2"));

        for (sequence, command, sql) in maintenance {
            recorder
                .append_global_dependency(
                    &RecorderEvent::MysqlQuery(mysql_query(connection_id, sequence, command, sql)),
                    "bootstrap_window",
                    "bootstrap",
                    "bootstrap_window",
                )
                .await
                .unwrap();
            recorder
                .append_global_dependency(
                    &RecorderEvent::MysqlExchange(mysql_exchange(
                        connection_id,
                        sequence,
                        command,
                        sql,
                    )),
                    "bootstrap_window",
                    "bootstrap",
                    "bootstrap_window",
                )
                .await
                .unwrap();
        }
        recorder
            .append_global_dependency(
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    connection_id,
                    5,
                    "COM_QUERY",
                    Some("SELECT 3"),
                )),
                "bootstrap_window",
                "bootstrap",
                "bootstrap_window",
            )
            .await
            .unwrap();
        recorder.flush_global_dependency_files().await.unwrap();

        let bootstrap_semantic = crate::recorder::test_io::read_to_string(
            recorder.run_dir.join("global-dependencies.jsonl"),
        )
        .await
        .unwrap();
        assert_eq!(bootstrap_semantic.lines().count(), 5);
        assert!(bootstrap_semantic.contains("SELECT 3"));
        assert!(bootstrap_semantic.contains("COM_PING"));
        assert!(bootstrap_semantic.contains("PROBABLYNOT"));
        assert!(bootstrap_semantic.contains("SELECT 1"));
        assert!(bootstrap_semantic.contains("SELECT 2"));

        let bootstrap_debug = crate::recorder::test_io::read_to_string(
            recorder.run_dir.join("global-dependencies-debug.jsonl"),
        )
        .await
        .unwrap();
        assert!(bootstrap_debug.contains("COM_PING"));
        assert!(bootstrap_debug.contains("PROBABLYNOT"));
        assert!(bootstrap_debug.contains("SELECT 1"));
        assert!(bootstrap_debug.contains("SELECT 2"));
    }

    #[tokio::test]
    async fn redis_quit_is_retained_as_a_control_fact() {
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
                .append_case_dependency(&case, event, "active_window")
                .await
                .unwrap();
        }
        let case_dir = recorder.case_staging_dir(&case);
        recorder
            .flush_case_dependency_files(&case_dir)
            .await
            .unwrap();

        let semantic =
            crate::recorder::test_io::read_to_string(case_dir.join("dependencies.jsonl"))
                .await
                .unwrap();
        assert!(semantic.contains("\"command\":\"GET\""));
        assert!(semantic.contains("\"command\":\"QUIT\""));
        let quit_fact = semantic
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|value| value["command"] == "QUIT")
            .unwrap();
        assert_eq!(quit_fact["capture"]["semantic_required"], false);

        super::super::summary::write_case_dependency_summary(&case_dir, recorder.evidence.clone())
            .await
            .unwrap();
        let summary =
            crate::recorder::test_io::read_to_string(case_dir.join("dependencies-summary.json"))
                .await
                .unwrap();
        assert!(summary.contains("\"GET\""));
        assert!(!summary.contains("\"QUIT\""));

        for event in [&quit, &get] {
            recorder
                .append_global_dependency(
                    event,
                    "bootstrap_window",
                    "bootstrap",
                    "bootstrap_window",
                )
                .await
                .unwrap();
        }
        recorder.flush_global_dependency_files().await.unwrap();

        let semantic = crate::recorder::test_io::read_to_string(
            recorder.run_dir.join("global-dependencies.jsonl"),
        )
        .await
        .unwrap();
        assert!(semantic.contains("\"command\":\"GET\""));
        assert!(semantic.contains("\"command\":\"QUIT\""));
        let quit_fact = semantic
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|value| value["command"] == "QUIT")
            .unwrap();
        assert_eq!(quit_fact["capture"]["semantic_required"], false);
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
            request_started_at: Utc::now(),
            timestamp: Utc::now(),
            client_addr: None,
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
            server_status_before: None,
            response: MysqlExchangeResponse {
                wire_prefix: Vec::new(),
                server_status: None,
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
            rpc_callback_capture: None,
            id: Uuid::new_v4(),
            connection_id,
            sequence,
            timestamp: Utc::now(),
            request_started_at: chrono::Utc::now(),
            client_addr: None,
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
            cache_snapshot_rule: None,
            cache_snapshot_hit: false,
            session_setup: false,
            outcome,
            duration_ms: 0,
            replay_safe: true,
            parse_warnings: Vec::new(),
        }
    }
}
