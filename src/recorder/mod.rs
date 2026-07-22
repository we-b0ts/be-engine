use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use self::run::{RecorderRunState, new_run_id};
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

use crate::config::{RecordingAccessPolicy, RecordingConfig, TrafficJsonlMode};

mod capture;
mod dependencies;
mod event;
pub(crate) mod http;
mod jsonl;
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
    traffic_file: Arc<Mutex<Option<jsonl::BufferedJsonlWriter>>>,
    traffic_jsonl: TrafficJsonlMode,
    dependency_files: Arc<Mutex<jsonl::JsonlWriterPool>>,
    pub(crate) run_dir: Arc<PathBuf>,
    pub(crate) run_state: Arc<Mutex<RecorderRunState>>,
    pub(crate) dependency_write_lock: Arc<Mutex<()>>,
    pub(crate) finalized_cases: Arc<Mutex<HashSet<Uuid>>>,
    pub(crate) access_policy: RecordingAccessPolicy,
}

impl Recorder {
    pub async fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        Self::new_with_access_policy(output_dir, RecordingAccessPolicy::Unrestricted).await
    }

    pub(crate) async fn new_with_access_policy(
        output_dir: impl AsRef<Path>,
        access_policy: RecordingAccessPolicy,
    ) -> Result<Self> {
        let defaults = RecordingConfig::default();
        Self::new_with_options(
            output_dir,
            access_policy,
            defaults.traffic_jsonl,
            jsonl::JsonlBufferSettings {
                capacity: defaults.jsonl_buffer_capacity_bytes,
                flush_interval: Duration::from_millis(defaults.jsonl_flush_interval_ms),
            },
            None,
        )
        .await
    }

    pub(crate) async fn new_with_recording_config_and_run_id(
        config: &RecordingConfig,
        run_id: Option<String>,
    ) -> Result<Self> {
        Self::new_with_options(
            &config.output_dir,
            config.access_policy,
            config.traffic_jsonl,
            jsonl::JsonlBufferSettings {
                capacity: config.jsonl_buffer_capacity_bytes,
                flush_interval: Duration::from_millis(config.jsonl_flush_interval_ms),
            },
            run_id,
        )
        .await
    }

    #[cfg(test)]
    async fn new_with_recording_config(config: &RecordingConfig) -> Result<Self> {
        Self::new_with_recording_config_and_run_id(config, None).await
    }

    async fn new_with_options(
        output_dir: impl AsRef<Path>,
        access_policy: RecordingAccessPolicy,
        traffic_jsonl: TrafficJsonlMode,
        buffer_settings: jsonl::JsonlBufferSettings,
        run_id: Option<String>,
    ) -> Result<Self> {
        let output_dir = output_dir.as_ref();
        tokio::fs::create_dir_all(output_dir)
            .await
            .with_context(|| format!("failed to create recording dir {}", output_dir.display()))?;
        let run_id = run_id.unwrap_or_else(new_run_id);
        anyhow::ensure!(
            run_id.len() == 14
                && run_id.bytes().all(|byte| byte.is_ascii_digit())
                && NaiveDateTime::parse_from_str(&run_id, "%Y%m%d%H%M%S").is_ok(),
            "recording run ID must be a valid 14-digit UTC timestamp"
        );
        let run_dir = output_dir.join(&run_id);
        tokio::fs::create_dir(&run_dir)
            .await
            .with_context(|| format!("failed to create recording run dir {}", run_dir.display()))?;
        let traffic_file = if traffic_jsonl == TrafficJsonlMode::Off {
            None
        } else {
            Some(
                jsonl::BufferedJsonlWriter::open(&run_dir.join("traffic.jsonl"), buffer_settings)
                    .await?,
            )
        };
        let recorder = Self {
            traffic_file: Arc::new(Mutex::new(traffic_file)),
            traffic_jsonl,
            dependency_files: Arc::new(Mutex::new(jsonl::JsonlWriterPool::new(buffer_settings))),
            run_dir: Arc::new(run_dir),
            run_state: Arc::new(Mutex::new(RecorderRunState {
                run_id,
                ..Default::default()
            })),
            dependency_write_lock: Arc::new(Mutex::new(())),
            finalized_cases: Arc::new(Mutex::new(HashSet::new())),
            access_policy,
        };
        spawn_jsonl_flush_task(
            &recorder.traffic_file,
            &recorder.dependency_files,
            buffer_settings.flush_interval,
        );
        recorder.write_run_report("running").await?;
        Ok(recorder)
    }

    pub async fn record(&self, event: RecorderEvent) -> Result<()> {
        if !should_write_traffic_event(self.traffic_jsonl, &event) {
            return Ok(());
        }
        let mut line = serde_json::to_vec(&event).context("failed to serialize recorder event")?;
        line.push(b'\n');

        let mut file = self.traffic_file.lock().await;
        if let Some(file) = file.as_mut() {
            file.append(&line).await?;
        }
        Ok(())
    }

    /// Flush currently buffered run-level `traffic.jsonl` records.
    pub async fn flush_traffic(&self) -> Result<()> {
        let mut file = self.traffic_file.lock().await;
        if let Some(file) = file.as_mut() {
            file.flush().await?;
        }
        Ok(())
    }

    pub async fn write_case_json<T: Serialize>(
        &self,
        case: &CaseContext,
        filename: &str,
        value: &T,
    ) -> Result<()> {
        let _guard = self.dependency_write_lock.lock().await;
        self.ensure_run_accepts_case_writes().await?;
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

fn spawn_jsonl_flush_task(
    traffic_file: &Arc<Mutex<Option<jsonl::BufferedJsonlWriter>>>,
    dependency_files: &Arc<Mutex<jsonl::JsonlWriterPool>>,
    interval: Duration,
) {
    let traffic_file = Arc::downgrade(traffic_file);
    let dependency_files = Arc::downgrade(dependency_files);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;

            let Some(traffic_file) = traffic_file.upgrade() else {
                break;
            };
            let traffic_flush = {
                let mut writer = traffic_file.lock().await;
                match writer.as_mut() {
                    Some(writer) => writer.flush().await,
                    None => Ok(()),
                }
            };
            drop(traffic_file);
            if let Err(error) = traffic_flush {
                warn!(%error, "failed to periodically flush traffic JSONL");
            }

            let Some(dependency_files) = dependency_files.upgrade() else {
                break;
            };
            let dependency_flush = dependency_files.lock().await.flush_open().await;
            drop(dependency_files);
            if let Err(error) = dependency_flush {
                warn!(%error, "failed to periodically flush dependency JSONL");
            }
        }
    });
}

fn should_write_traffic_event(mode: TrafficJsonlMode, event: &RecorderEvent) -> bool {
    match mode {
        TrafficJsonlMode::Full => true,
        TrafficJsonlMode::Off => false,
        TrafficJsonlMode::Errors => match event {
            RecorderEvent::HttpExchange(event) => {
                event.error.is_some() || event.response_status.is_some_and(|status| status >= 500)
            }
            RecorderEvent::TcpGatewayConnection(event) => event.error.is_some(),
            RecorderEvent::UdpDatagram(event) => event.error.is_some(),
            RecorderEvent::RedisConnection(event) => event.error.is_some(),
            RecorderEvent::MemcachedConnection(event) => event.error.is_some(),
            RecorderEvent::KafkaConnection(event) => event.error.is_some(),
            RecorderEvent::MysqlConnection(event) => event.error.is_some(),
            RecorderEvent::MysqlPacket(event) => event.error_code.is_some(),
            RecorderEvent::MysqlResponse(event) => event.error_code.is_some(),
            RecorderEvent::MysqlExchange(event) => event.response.error_code.is_some(),
            RecorderEvent::MysqlTlsRejected(_)
            | RecorderEvent::AccessPolicyAllow(_)
            | RecorderEvent::ReadonlyRejection(_)
            | RecorderEvent::ProxyError(_) => true,
            RecorderEvent::RedisExchange(_)
            | RecorderEvent::MemcachedExchange(_)
            | RecorderEvent::KafkaProduce(_)
            | RecorderEvent::KafkaDelivery(_)
            | RecorderEvent::MysqlQuery(_) => false,
        },
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

    async fn flush_case_dependencies(recorder: &Recorder, case: &CaseContext) {
        let _guard = recorder.dependency_write_lock.lock().await;
        recorder
            .flush_case_dependency_files(&recorder.case_staging_dir(case))
            .await
            .unwrap();
    }

    async fn flush_bootstrap_dependencies(recorder: &Recorder) {
        let _guard = recorder.dependency_write_lock.lock().await;
        recorder.flush_bootstrap_dependency_files().await.unwrap();
    }

    fn test_proxy_error(message: &str) -> RecorderEvent {
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            protocol: "test".to_string(),
            client_addr: None,
            client_process: None,
            target: Some("upstream".to_string()),
            error: message.to_string(),
        })
    }

    fn test_mysql_query() -> RecorderEvent {
        RecorderEvent::MysqlQuery(MysqlQueryEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sequence: 1,
            timestamp: Utc::now(),
            client_addr: None,
            client_process: None,
            command: "COM_QUERY".to_string(),
            query: Some("select 1".to_string()),
            payload_len: 8,
        })
    }

    #[tokio::test]
    async fn traffic_jsonl_off_skips_the_file() {
        let temp = tempfile::tempdir().unwrap();
        let config = RecordingConfig {
            output_dir: temp.path().to_path_buf(),
            traffic_jsonl: TrafficJsonlMode::Off,
            ..Default::default()
        };
        let recorder = Recorder::new_with_recording_config(&config).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".to_string(),
            uri_group: None,
        };
        let event = test_proxy_error("boom");

        recorder.record(event.clone()).await.unwrap();
        recorder
            .append_case_dependency(&case, &event, "active_window")
            .await
            .unwrap();
        recorder.publish_case(&case).await.unwrap();
        recorder.finish_run().await.unwrap();

        assert!(!recorder.run_dir.join("traffic.jsonl").exists());
        let dependencies =
            tokio::fs::read_to_string(recorder.case_dir(&case).join("dependencies.jsonl"))
                .await
                .unwrap();
        assert!(dependencies.contains("\"event_type\":\"proxy_error\""));
    }

    #[tokio::test]
    async fn traffic_jsonl_errors_keeps_only_diagnostic_events() {
        let temp = tempfile::tempdir().unwrap();
        let config = RecordingConfig {
            output_dir: temp.path().to_path_buf(),
            traffic_jsonl: TrafficJsonlMode::Errors,
            ..Default::default()
        };
        let recorder = Recorder::new_with_recording_config(&config).await.unwrap();

        recorder.record(test_mysql_query()).await.unwrap();
        recorder.record(test_proxy_error("boom")).await.unwrap();
        recorder.finish_run().await.unwrap();

        let raw = tokio::fs::read_to_string(recorder.run_dir.join("traffic.jsonl"))
            .await
            .unwrap();
        assert_eq!(raw.lines().count(), 1);
        assert!(raw.contains("\"event_type\":\"proxy_error\""));
    }

    #[tokio::test]
    async fn traffic_jsonl_full_flushes_buffer_when_run_finishes() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let path = recorder.run_dir.join("traffic.jsonl");

        recorder.record(test_proxy_error("boom")).await.unwrap();
        assert!(tokio::fs::read(&path).await.unwrap().is_empty());

        recorder.finish_run().await.unwrap();
        assert!(!tokio::fs::read(&path).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn traffic_jsonl_flushes_on_the_configured_interval() {
        let temp = tempfile::tempdir().unwrap();
        let config = RecordingConfig {
            output_dir: temp.path().to_path_buf(),
            jsonl_flush_interval_ms: 10,
            ..Default::default()
        };
        let recorder = Recorder::new_with_recording_config(&config).await.unwrap();
        let path = recorder.run_dir.join("traffic.jsonl");

        recorder.record(test_proxy_error("boom")).await.unwrap();
        assert!(tokio::fs::read(&path).await.unwrap().is_empty());

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !tokio::fs::read(&path).await.unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn explicit_run_id_uses_exact_directory_and_rejects_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "20260721153045";
        let config = RecordingConfig {
            output_dir: temp.path().to_path_buf(),
            ..RecordingConfig::default()
        };
        let recorder =
            Recorder::new_with_recording_config_and_run_id(&config, Some(run_id.to_string()))
                .await
                .unwrap();
        assert_eq!(recorder.run_dir.as_ref(), &temp.path().join(run_id));
        drop(recorder);

        let error =
            match Recorder::new_with_recording_config_and_run_id(&config, Some(run_id.to_string()))
                .await
            {
                Ok(_) => panic!("duplicate explicit run ID must fail"),
                Err(error) => error,
            };
        assert!(format!("{error:#}").contains("failed to create recording run dir"));
    }

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
        flush_case_dependencies(&recorder, &case).await;

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
        flush_case_dependencies(&recorder, &case).await;

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
        flush_bootstrap_dependencies(&recorder).await;

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

        flush_case_dependencies(&recorder, &case).await;

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

        flush_case_dependencies(&recorder, &case).await;

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
        flush_case_dependencies(&recorder, &case).await;

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
        let published_case_dir = recorder
            .run_dir
            .join("record-api")
            .join("api-users")
            .join(case.id.to_string());
        assert!(published_case_dir.join("request.json").exists());
        let dependencies = tokio::fs::read_to_string(published_case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert!(dependencies.is_empty());
        let summary_raw =
            tokio::fs::read_to_string(published_case_dir.join("dependencies-summary.json"))
                .await
                .unwrap();
        let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
        assert_eq!(summary["source"], "dependencies.jsonl");
        assert_eq!(summary["total_events"], 0);
        assert_eq!(summary["event_types"], serde_json::json!({}));
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
        let published_case_dir = recorder
            .run_dir
            .join("record-api")
            .join("api-users")
            .join(case.id.to_string());
        let dependencies = tokio::fs::read_to_string(published_case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
        assert!(dependencies.is_empty());
        let summary_raw =
            tokio::fs::read_to_string(published_case_dir.join("dependencies-summary.json"))
                .await
                .unwrap();
        let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
        assert_eq!(summary["total_events"], 0);
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
        flush_bootstrap_dependencies(&recorder).await;

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
