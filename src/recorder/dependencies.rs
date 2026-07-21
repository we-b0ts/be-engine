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
    )
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
