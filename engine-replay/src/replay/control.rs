use super::*;
use std::time::{Duration, Instant};
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const READY_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
pub const MAX_CONTROL_BYTES: usize = 16 * 1024 * 1024;
pub mod derived_input;
pub mod input_timing;
pub mod native_event;
pub mod primary_close;
pub use derived_input::register as register_derived_input;
pub use input_timing::connect as input_timing_observer;
pub use native_event::connect as native_event_observer;
pub use primary_close::connect as primary_close_observer;
#[derive(Debug, Clone, Copy)]
pub enum FinalizationScope {
    WholeSession,
    SelectedCases,
}
impl FinalizationScope {
    pub fn command(self) -> &'static str {
        match self {
            Self::WholeSession => "finalize",
            Self::SelectedCases => "finalize_cases",
        }
    }
    pub fn from_command(command: &str) -> Self {
        if command == Self::SelectedCases.command() {
            Self::SelectedCases
        } else {
            Self::WholeSession
        }
    }
}
pub async fn send_control_request(config: MysqlReplayControlConfig) -> Result<Value> {
    if config.command == "wait_ready" {
        let timeout = config.wait_timeout.unwrap_or(DEFAULT_READY_TIMEOUT);
        let started = Instant::now();
        let mut next_progress = READY_PROGRESS_INTERVAL;
        tracing::info!(
            timeout_seconds = timeout.as_secs(),
            session = %config.session_path.display(),
            "waiting for replay session readiness"
        );
        loop {
            let error = match send_control_request_once(config.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => err,
            };
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(error).with_context(|| {
                    format!(
                        "replay session did not become ready within {} seconds",
                        timeout.as_secs()
                    )
                });
            }
            if elapsed >= next_progress {
                tracing::info!(
                    elapsed_seconds = elapsed.as_secs(),
                    timeout_seconds = timeout.as_secs(),
                    session = %config.session_path.display(),
                    "still waiting for replay session readiness"
                );
                next_progress += READY_PROGRESS_INTERVAL;
            }
            tokio::time::sleep(READY_POLL_INTERVAL.min(timeout.saturating_sub(elapsed))).await;
        }
    }
    send_control_request_once(config).await
}

pub async fn send_control_request_once(config: MysqlReplayControlConfig) -> Result<Value> {
    let session_raw = tokio::fs::read_to_string(&config.session_path)
        .await
        .with_context(|| {
            format!(
                "failed to read replay session {}",
                config.session_path.display()
            )
        })?;
    let session: Value =
        serde_json::from_str(&session_raw).context("failed to parse replay session JSON")?;
    let control_socket = session
        .get("control_socket")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("replay session has no control_socket"))?;
    let pid = session.get("pid").and_then(Value::as_u64);
    if let Some(pid) = pid
        && !process_exists(pid)
    {
        return Err(anyhow!(
            "replay session process {pid} is not running for {}",
            config.session_path.display()
        ));
    }

    let request = serde_json::json!({
        "command": config.command,
        "case_id": config.case_id,
        "fail_on_dirty": config.fail_on_dirty,
        "fail_on_incomplete": config.fail_on_incomplete,
    });
    let mut stream = UnixStream::connect(control_socket)
        .await
        .with_context(|| format!("failed to connect replay control socket {control_socket}"))?;
    let mut payload =
        serde_json::to_vec(&request).context("failed to serialize replay control request")?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .await
        .context("failed to write replay control request")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("failed to read replay control response")?;
    let response: Value =
        serde_json::from_str(line.trim()).context("failed to parse replay control response")?;
    if response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        Ok(response)
    } else {
        Err(anyhow!(control_failure_message(&response, &session)))
    }
}

fn control_failure_message(response: &Value, session: &Value) -> String {
    let mut message = response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("replay control command failed")
        .to_owned();
    for field in ["complete", "dirty", "finalized"] {
        if let Some(value) = response.get(field).and_then(Value::as_bool) {
            message.push_str(&format!("; {field}={value}"));
        }
    }
    if let Some(report_path) = session
        .get("report_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        message.push_str("; inspect replay report at ");
        message.push_str(report_path);
    }
    message
}

pub fn process_exists(pid: u64) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod client_tests {
    use super::*;
    #[test]
    fn failure_references_report_without_embedding_it() {
        let response = serde_json::json!({
            "ok": false,
            "complete": true,
            "dirty": true,
            "error": "replay evidence is dirty",
            "report": {"large_payload": "x".repeat(1_000_000)},
        });
        let session = serde_json::json!({"report_path": "/tmp/replay-report.json"});

        let message = control_failure_message(&response, &session);

        assert!(message.contains("complete=true; dirty=true"));
        assert!(message.contains("/tmp/replay-report.json"));
        assert!(!message.contains("large_payload"));
        assert!(message.len() < 256);
    }
}
