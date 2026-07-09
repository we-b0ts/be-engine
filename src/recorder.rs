use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::dependency_summary::{
    should_append_case_dependency, write_bootstrap_dependency_summary,
    write_case_dependency_summary,
};
use crate::recorder_run::{RecorderRunState, new_run_id};
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use flate2::read::{GzDecoder, ZlibDecoder};
use hyper::HeaderMap;
use serde::Serialize;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

pub use crate::recorder_event::*;

#[derive(Clone)]
pub struct Recorder {
    file: Arc<Mutex<File>>,
    pub(crate) output_dir: Arc<PathBuf>,
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
        let path = output_dir.join("traffic.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open JSONL recording file {}", path.display()))?;
        let run_id = new_run_id();
        let run_dir = output_dir.join("_runs").join(&run_id);
        tokio::fs::create_dir_all(&run_dir)
            .await
            .with_context(|| format!("failed to create recording run dir {}", run_dir.display()))?;
        let recorder = Self {
            file: Arc::new(Mutex::new(file)),
            output_dir: Arc::new(output_dir.to_path_buf()),
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
        if self.finalized_cases.lock().await.contains(&case.id) {
            return Ok(());
        }
        let dir = self.case_staging_dir(case);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("failed to create case recording dir {}", dir.display()))?;
        let filename = case_dependency_filename(event);
        let path = dir.join(filename);
        let mut value =
            serde_json::to_value(event).context("failed to serialize case dependency event")?;
        compact_case_dependency_process_info(&mut value);
        if let serde_json::Value::Object(object) = &mut value {
            object.insert(
                "case_dependency_matched_by".to_string(),
                serde_json::Value::String(matched_by.to_string()),
            );
        }
        let mut line =
            serde_json::to_vec(&value).context("failed to serialize case dependency event")?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open case dependencies file {}", path.display()))?;
        file.write_all(&line)
            .await
            .context("failed to append case dependency event")?;
        file.flush()
            .await
            .context("failed to flush case dependency event")?;
        if filename == "dependencies.jsonl" {
            write_case_dependency_summary(&dir).await?;
        }
        Ok(())
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
        tokio::fs::create_dir_all(&*self.output_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create recording dir {}",
                    self.output_dir.display()
                )
            })?;
        let filename = bootstrap_dependency_filename(event);
        let path = self.output_dir.join(filename);
        let mut value = serde_json::to_value(event)
            .context("failed to serialize bootstrap dependency event")?;
        compact_case_dependency_process_info(&mut value);
        if let serde_json::Value::Object(object) = &mut value {
            object.insert(
                "bootstrap_dependency_matched_by".to_string(),
                serde_json::Value::String(matched_by.to_string()),
            );
        }
        let mut line =
            serde_json::to_vec(&value).context("failed to serialize bootstrap dependency event")?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| {
                format!(
                    "failed to open bootstrap dependencies file {}",
                    path.display()
                )
            })?;
        file.write_all(&line)
            .await
            .context("failed to append bootstrap dependency event")?;
        file.flush()
            .await
            .context("failed to flush bootstrap dependency event")?;
        if filename == "bootstrap-dependencies.jsonl" {
            write_bootstrap_dependency_summary(&self.output_dir).await?;
        }
        Ok(())
    }
}

fn case_dependency_filename(event: &RecorderEvent) -> &'static str {
    if is_case_dependency_debug_event(event) {
        "dependencies-debug.jsonl"
    } else {
        "dependencies.jsonl"
    }
}

fn bootstrap_dependency_filename(event: &RecorderEvent) -> &'static str {
    if is_case_dependency_debug_event(event) {
        "bootstrap-dependencies-debug.jsonl"
    } else {
        "bootstrap-dependencies.jsonl"
    }
}

fn is_case_dependency_debug_event(event: &RecorderEvent) -> bool {
    matches!(
        event,
        RecorderEvent::MysqlQuery(_)
            | RecorderEvent::MysqlResponse(_)
            | RecorderEvent::MysqlPacket(_)
    )
}

fn compact_case_dependency_process_info(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(process) = object.get_mut("client_process")
                && let Some(pid) = process.get("pid").and_then(serde_json::Value::as_u64)
            {
                *process = serde_json::Value::Number(pid.into());
            }
            for child in object.values_mut() {
                compact_case_dependency_process_info(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                compact_case_dependency_process_info(child);
            }
        }
        _ => {}
    }
}

pub fn capture_body(bytes: &[u8], max_body_bytes: usize) -> BodyCapture {
    let stored_len = bytes.len().min(max_body_bytes);
    capture_body_with_original_len(&bytes[..stored_len], bytes.len())
}

pub fn capture_body_with_original_len(bytes: &[u8], original_len: usize) -> BodyCapture {
    BodyCapture {
        encoding: "base64",
        original_len,
        stored_len: bytes.len(),
        truncated: original_len > bytes.len(),
        data: STANDARD.encode(bytes),
    }
}

pub fn capture_case_body(
    bytes: &[u8],
    max_body_bytes: usize,
    headers: Option<&HeaderMap>,
) -> CaseBodyCapture {
    let content_encoding = headers.and_then(content_encoding);
    let (body, decoded, decode_error) = match content_encoding.as_deref() {
        Some(encoding) => match decode_content_encoding(bytes, encoding) {
            Ok(decoded) => (decoded, true, None),
            Err(err) => (bytes.to_vec(), false, Some(err.to_string())),
        },
        None => (bytes.to_vec(), false, None),
    };
    let stored_len = body.len().min(max_body_bytes);
    let stored = &body[..stored_len];
    match std::str::from_utf8(stored) {
        Ok(text) => CaseBodyCapture {
            encoding: "utf8",
            original_len: bytes.len(),
            stored_len,
            truncated: body.len() > max_body_bytes,
            decoded,
            content_encoding,
            data: text.to_string(),
            decode_error,
        },
        Err(_) => CaseBodyCapture {
            encoding: "base64",
            original_len: bytes.len(),
            stored_len,
            truncated: body.len() > max_body_bytes,
            decoded,
            content_encoding,
            data: STANDARD.encode(stored),
            decode_error,
        },
    }
}

pub fn redact_headers(headers: &HeaderMap, sensitive_names: &[String]) -> HeaderMapSnapshot {
    let sensitive = sensitive_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut out = HeaderMapSnapshot::new();

    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        let rendered = if sensitive.contains(&name) {
            "<redacted>".to_string()
        } else {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes()))
        };
        out.entry(name).or_default().push(rendered);
    }

    out
}

fn content_encoding(headers: &HeaderMap) -> Option<String> {
    headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn decode_content_encoding(bytes: &[u8], encoding: &str) -> Result<Vec<u8>> {
    let mut out = bytes.to_vec();
    for coding in encoding
        .split(',')
        .map(str::trim)
        .filter(|coding| !coding.is_empty())
        .rev()
    {
        out = match coding {
            "gzip" | "x-gzip" => {
                let mut decoder = GzDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .read_to_end(&mut decoded)
                    .context("failed to decode gzip body")?;
                decoded
            }
            "deflate" => {
                let mut decoder = ZlibDecoder::new(out.as_slice());
                let mut decoded = Vec::new();
                decoder
                    .read_to_end(&mut decoded)
                    .context("failed to decode deflate body")?;
                decoded
            }
            "identity" => out,
            other => anyhow::bail!("unsupported content-encoding {other}"),
        };
    }
    Ok(out)
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

impl From<Bytes> for BodyCapture {
    fn from(value: Bytes) -> Self {
        capture_body(&value, value.len())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};

    use super::*;

    #[test]
    fn captures_body_with_truncation() {
        let capture = capture_body(b"abcdef", 3);
        assert_eq!(capture.original_len, 6);
        assert_eq!(capture.stored_len, 3);
        assert!(capture.truncated);
        assert_eq!(capture.data, "YWJj");
    }

    #[test]
    fn captures_case_body_with_gzip_decoding() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(br#"{"ok":true}"#).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());

        let capture = capture_case_body(&compressed, 1024, Some(&headers));
        assert_eq!(capture.encoding, "utf8");
        assert!(capture.decoded);
        assert_eq!(capture.data, r#"{"ok":true}"#);
    }

    #[test]
    fn redacts_sensitive_headers_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        headers.insert(COOKIE, HeaderValue::from_static("a=b"));

        let snapshot = redact_headers(&headers, &["authorization".into(), "cookie".into()]);
        assert_eq!(snapshot["authorization"], vec!["<redacted>".to_string()]);
        assert_eq!(snapshot["cookie"], vec!["<redacted>".to_string()]);
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
    async fn bootstrap_dependency_writes_root_file_and_summary() {
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

        let raw = tokio::fs::read_to_string(temp.path().join("bootstrap-dependencies.jsonl"))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(value["event_type"], "proxy_error");
        assert_eq!(value["client_process"], 42);
        assert_eq!(value["bootstrap_dependency_matched_by"], "bootstrap_window");

        let summary_raw =
            tokio::fs::read_to_string(temp.path().join("bootstrap-dependencies-summary.json"))
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
            temp.path()
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
            !temp
                .path()
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
            !temp
                .path()
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

        assert!(!temp.path().join("bootstrap-dependencies.jsonl").exists());
        let raw = tokio::fs::read_to_string(temp.path().join("bootstrap-dependencies-debug.jsonl"))
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
