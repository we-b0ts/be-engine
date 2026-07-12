use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use self::run::{RecorderRunState, new_run_id};
use anyhow::{Context, Result};
use serde::Serialize;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

mod capture;
mod dependencies;
mod event;
pub(crate) mod http;
pub(crate) mod kafka;
pub(crate) mod memcached;
pub(crate) mod mysql;
pub(crate) mod redis;
mod run;
mod summary;

pub use capture::*;
pub use event::*;

#[derive(Clone)]
pub struct Recorder {
    file: Arc<Mutex<File>>,
    pub(crate) run_dir: Arc<PathBuf>,
    pub(crate) run_state: Arc<Mutex<RecorderRunState>>,
    pub(crate) dependency_write_lock: Arc<Mutex<()>>,
    pub(crate) finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
}

impl Recorder {
    pub async fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        let output_dir = output_dir.as_ref();
        tokio::fs::create_dir_all(output_dir)
            .await
            .with_context(|| format!("failed to create recording dir {}", output_dir.display()))?;
        let run_id = new_run_id();
        let run_dir = output_dir.join(&run_id);
        tokio::fs::create_dir(&run_dir)
            .await
            .with_context(|| format!("failed to create recording run dir {}", run_dir.display()))?;
        let path = run_dir.join("traffic.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open JSONL recording file {}", path.display()))?;
        let recorder = Self {
            file: Arc::new(Mutex::new(file)),
            run_dir: Arc::new(run_dir),
            run_state: Arc::new(Mutex::new(RecorderRunState {
                run_id,
                ..Default::default()
            })),
            dependency_write_lock: Arc::new(Mutex::new(())),
            finalized_cases: Arc::new(Mutex::new(HashSet::new())),
        };
        recorder.write_run_report("running").await?;
        Ok(recorder)
    }

    pub async fn record(&self, event: RecorderEvent) -> Result<()> {
        let mut line = serde_json::to_vec(&event).context("failed to serialize recorder event")?;
        line.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&line)
            .await
            .context("failed to append recorder event")?;
        file.flush()
            .await
            .context("failed to flush recorder event")?;
        Ok(())
    }

    pub async fn write_case_json<T: Serialize>(
        &self,
        case: &CaseContext,
        filename: &str,
        value: &T,
    ) -> Result<()> {
        let path = self.case_staging_dir(case).join(filename);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create case recording dir {}", parent.display())
            })?;
        }
        let mut payload =
            serde_json::to_vec_pretty(value).context("failed to serialize case recording file")?;
        payload.push(b'\n');
        tokio::fs::write(&path, payload)
            .await
            .with_context(|| format!("failed to write case recording file {}", path.display()))
    }
}

pub(crate) fn sanitize_path_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unnamed".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    #[tokio::test]
    async fn case_dependency_records_match_reason() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: None,
            target: Some("upstream".to_string()),
            error: "boom".to_string(),
        });

        recorder
            .append_case_dependency(&case, &event, "active_window")
            .await
            .unwrap();

        let raw =
            tokio::fs::read_to_string(recorder.case_staging_dir(&case).join("dependencies.jsonl"))
                .await
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "proxy_error");
        assert_eq!(value["case_dependency_matched_by"], "active_window");
    }

    #[tokio::test]
    async fn case_files_include_uri_group_when_present() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record api".to_string(),
            uri_group: Some("api-users".to_string()),
        };

        recorder
            .write_case_json(&case, "request.json", &serde_json::json!({ "ok": true }))
            .await
            .unwrap();

        assert!(
            recorder
                .case_staging_dir(&case)
                .join("request.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn case_dependency_compacts_client_process_to_pid() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: Some(ProcessInfo {
                pid: 42,
                comm: Some("app".to_string()),
                cmdline: Some("app --serve".to_string()),
                exe: Some("/tmp/app".to_string()),
            }),
            target: Some("upstream".to_string()),
            error: "boom".to_string(),
        });

        recorder
            .append_case_dependency(&case, &event, "process")
            .await
            .unwrap();

        let raw =
            tokio::fs::read_to_string(recorder.case_staging_dir(&case).join("dependencies.jsonl"))
                .await
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["case_dependency_matched_by"], "process");
    }

    #[tokio::test]
    async fn bootstrap_dependency_writes_run_file_and_summary() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: Some(ProcessInfo {
                pid: 42,
                comm: Some("app".to_string()),
                cmdline: Some("app --serve".to_string()),
                exe: Some("/tmp/app".to_string()),
            }),
            target: Some("upstream".to_string()),
            error: "boom".to_string(),
        });

        recorder
            .append_bootstrap_dependency(&event, "bootstrap_window")
            .await
            .unwrap();

        let raw = tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies.jsonl"))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "proxy_error");
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["bootstrap_dependency_matched_by"], "bootstrap_window");

        summary::write_bootstrap_dependency_summary(&recorder.run_dir)
            .await
            .unwrap();
        let summary_raw =
            tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies-summary.json"))
                .await
                .unwrap();
        let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
        assert_eq!(summary["total_events"], 1);
        assert_eq!(summary["event_types"]["proxy_error"], 1);
    }

    #[tokio::test]
    async fn case_dependency_summary_skips_successful_prepare() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };

        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_STMT_PREPARE",
                    Some("SELECT `id`, `name` FROM `user` WHERE `id` = ?"),
                    "stmt_prepare",
                    vec![mysql_column("id", "user", "id", "integer", "INT")],
                    Vec::new(),
                    None,
                    None,
                )),
                "process",
            )
            .await
            .unwrap();

        let case_dir = recorder.case_staging_dir(&case);
        assert!(!case_dir.join("dependencies.jsonl").exists());
        assert!(!case_dir.join("dependencies-summary.json").exists());

        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_STMT_EXECUTE",
                    Some("SELECT `id`, `name` FROM `user` WHERE `id` = ?"),
                    "resultset",
                    vec![
                        mysql_column("id", "user", "id", "integer", "INT"),
                        mysql_column("name", "user", "name", "string", "VARCHAR"),
                    ],
                    vec![vec![
                        MysqlValue {
                            kind: "integer".to_string(),
                            value: Some(serde_json::json!(1)),
                            raw: None,
                        },
                        MysqlValue {
                            kind: "string".to_string(),
                            value: Some(serde_json::json!("alice")),
                            raw: None,
                        },
                    ]],
                    None,
                    None,
                )),
                "process",
            )
            .await
            .unwrap();

        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_STMT_PREPARE",
                    Some("INSERT INTO request_log_202607 (uuid) VALUES (?)"),
                    "error",
                    Vec::new(),
                    Vec::new(),
                    Some(1146),
                    Some("Table 'pluto_log.request_log_202607' doesn't exist"),
                )),
                "process",
            )
            .await
            .unwrap();

        let raw = tokio::fs::read_to_string(case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert_eq!(raw.lines().count(), 2);
        assert!(!raw.contains("\"status\":\"stmt_prepare\""));

        summary::write_case_dependency_summary(&case_dir)
            .await
            .unwrap();
        let summary_raw = tokio::fs::read_to_string(case_dir.join("dependencies-summary.json"))
            .await
            .unwrap();
        let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
        assert_eq!(summary["total_events"], 2);
        assert_eq!(summary["event_types"]["mysql_exchange"], 2);
        assert_eq!(summary["mysql"]["semantic_exchanges"], 2);
        assert_eq!(summary["mysql"]["executed"]["total"], 1);
        assert_eq!(summary["mysql"]["executed"]["crud"]["select"], 1);
        assert_eq!(summary["mysql"]["failed"]["total"], 1);
        assert_eq!(summary["mysql"]["failed"]["by_phase"]["prepare"], 1);
        assert_eq!(summary["mysql"]["failed"]["crud"]["insert"], 1);
        assert_eq!(summary["mysql"]["tables"]["user"]["executed"]["select"], 1);
        assert_eq!(
            summary["mysql"]["tables"]["request_log_202607"]["failed"]["insert"],
            1
        );
    }

    #[tokio::test]
    async fn case_dependency_skips_successful_mysql_session_setup() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };

        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_QUERY",
                    Some("SET NAMES utf8"),
                    "ok",
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                )),
                "process",
            )
            .await
            .unwrap();

        let case_dir = recorder.case_staging_dir(&case);
        assert!(!case_dir.join("dependencies.jsonl").exists());
        assert!(!case_dir.join("dependencies-summary.json").exists());

        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_QUERY",
                    Some("SET @tenant_id = 1"),
                    "ok",
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                )),
                "process",
            )
            .await
            .unwrap();

        let raw = tokio::fs::read_to_string(case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert_eq!(raw.lines().count(), 1);
        assert!(raw.contains("SET @tenant_id = 1"));
        assert!(!raw.contains("SET NAMES utf8"));
    }

    #[tokio::test]
    async fn case_dependency_routes_mysql_protocol_details_to_debug_file() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let event = RecorderEvent::MysqlQuery(MysqlQueryEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sequence: 1,
            timestamp: Utc::now(),
            client_addr: Some("127.0.0.1:12345".to_string()),
            client_process: Some(ProcessInfo {
                pid: 42,
                comm: Some("app".to_string()),
                cmdline: Some("app --serve".to_string()),
                exe: Some("/tmp/app".to_string()),
            }),
            command: "COM_QUERY".to_string(),
            query: Some("select 1".to_string()),
            payload_len: 9,
        });

        recorder
            .append_case_dependency(&case, &event, "process")
            .await
            .unwrap();

        let case_dir = recorder.case_staging_dir(&case);
        assert!(!case_dir.join("dependencies.jsonl").exists());
        let raw = tokio::fs::read_to_string(case_dir.join("dependencies-debug.jsonl"))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "mysql_query");
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["case_dependency_matched_by"], "process");
    }

    #[tokio::test]
    async fn publish_case_moves_staging_to_published_and_updates_report() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record api".to_string(),
            uri_group: Some("api-users".to_string()),
        };

        recorder
            .write_case_json(&case, "request.json", &serde_json::json!({ "ok": true }))
            .await
            .unwrap();
        recorder.publish_case(&case).await.unwrap();

        assert!(!recorder.case_staging_dir(&case).exists());
        assert!(
            recorder
                .run_dir
                .join("record-api")
                .join("api-users")
                .join(case.id.to_string())
                .join("request.json")
                .exists()
        );
        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["published_cases"], 1);
        assert_eq!(report["failed_cases"], 0);
    }

    #[tokio::test]
    async fn finalized_case_ignores_late_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record api".to_string(),
            uri_group: Some("api-users".to_string()),
        };
        let event = RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: None,
            target: Some("upstream".to_string()),
            error: "late".to_string(),
        });

        recorder
            .write_case_json(&case, "request.json", &serde_json::json!({ "ok": true }))
            .await
            .unwrap();
        recorder.publish_case(&case).await.unwrap();
        recorder
            .append_case_dependency(&case, &event, "active_window")
            .await
            .unwrap();

        assert!(!recorder.case_staging_dir(&case).exists());
        assert!(
            !recorder
                .run_dir
                .join("record-api")
                .join("api-users")
                .join(case.id.to_string())
                .join("dependencies.jsonl")
                .exists()
        );
    }

    #[tokio::test]
    async fn fail_case_moves_staging_to_failed_and_records_error() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record api".to_string(),
            uri_group: Some("api-users".to_string()),
        };

        recorder
            .write_case_json(
                &case,
                "expected-response.json.truncated",
                &serde_json::json!({ "truncated": true }),
            )
            .await
            .unwrap();
        recorder
            .fail_case(
                &case,
                "expected_response_body_truncated",
                "response exceeded recording limit",
            )
            .await
            .unwrap();

        assert!(!recorder.case_staging_dir(&case).exists());
        let failed_dir = recorder.case_failed_dir(&case);
        assert!(failed_dir.join("expected-response.json.truncated").exists());
        assert!(failed_dir.join("recording-error.json").exists());
        assert!(
            !recorder
                .run_dir
                .join("record-api")
                .join("api-users")
                .join(case.id.to_string())
                .exists()
        );
        let errors_raw = tokio::fs::read_to_string(recorder.run_dir.join("errors.jsonl"))
            .await
            .unwrap();
        assert!(errors_raw.contains("expected_response_body_truncated"));
        let report_raw = tokio::fs::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
        let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["published_cases"], 0);
        assert_eq!(report["failed_cases"], 1);
    }

    #[tokio::test]
    async fn bootstrap_dependency_routes_mysql_protocol_details_to_debug_file() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let event = RecorderEvent::MysqlQuery(MysqlQueryEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sequence: 1,
            timestamp: Utc::now(),
            client_addr: Some("127.0.0.1:12345".to_string()),
            client_process: Some(ProcessInfo {
                pid: 42,
                comm: Some("app".to_string()),
                cmdline: Some("app --serve".to_string()),
                exe: Some("/tmp/app".to_string()),
            }),
            command: "COM_QUERY".to_string(),
            query: Some("select 1".to_string()),
            payload_len: 9,
        });

        recorder
            .append_bootstrap_dependency(&event, "bootstrap_window")
            .await
            .unwrap();

        assert!(
            !recorder
                .run_dir
                .join("bootstrap-dependencies.jsonl")
                .exists()
        );
        let raw =
            tokio::fs::read_to_string(recorder.run_dir.join("bootstrap-dependencies-debug.jsonl"))
                .await
                .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "mysql_query");
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["bootstrap_dependency_matched_by"], "bootstrap_window");
    }

    fn mysql_exchange(
        command: &str,
        sql: Option<&str>,
        status: &str,
        columns: Vec<MysqlColumn>,
        rows: Vec<Vec<MysqlValue>>,
        error_code: Option<u16>,
        error_message: Option<&str>,
    ) -> MysqlExchangeEvent {
        MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            query_sequence: 1,
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
            statement_id: Some(1),
            params: None,
            response: MysqlExchangeResponse {
                status: status.to_string(),
                error_code,
                error_message: error_message.map(ToOwned::to_owned),
                affected_rows: None,
                last_insert_id: None,
                row_count: rows.len(),
                rows,
                columns,
                rows_truncated: false,
            },
            duration_ms: 1,
            parse_warnings: Vec::new(),
        }
    }

    fn mysql_column(
        name: &str,
        table: &str,
        column: &str,
        family: &str,
        sql_type: &str,
    ) -> MysqlColumn {
        MysqlColumn {
            name: name.to_string(),
            table: Some(table.to_string()),
            column: Some(column.to_string()),
            family: family.to_string(),
            sql_type: sql_type.to_string(),
            unsigned: None,
            bits: None,
            nullable: Some(false),
            scale: None,
            column_type_code: 0,
            flags: None,
        }
    }
}
