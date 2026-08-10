use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use chrono::Utc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::AppState;

use super::{ProxyErrorEvent, RecorderEvent};

const RAW_COPY_BUFFER_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RawTrafficDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug)]
struct CaptureStatus {
    reason: Option<String>,
    last_reported_case: Option<Uuid>,
}

#[derive(Debug)]
pub(super) struct ConnectionCaptureHealth {
    connection_id: Uuid,
    protocol: &'static str,
    client_addr: Option<String>,
    target: String,
    degraded: AtomicBool,
    status: Mutex<CaptureStatus>,
}

impl ConnectionCaptureHealth {
    pub(super) fn new(
        connection_id: Uuid,
        protocol: &'static str,
        client_addr: Option<String>,
        target: String,
    ) -> Self {
        Self {
            connection_id,
            protocol,
            client_addr,
            target,
            degraded: AtomicBool::new(false),
            status: Mutex::new(CaptureStatus {
                reason: None,
                last_reported_case: None,
            }),
        }
    }

    pub(super) fn activate(&self, state: &AppState, reason: String) {
        let targets = state.capture_dependency_targets();
        let current_case = targets.cases.first().map(|(case, _)| case.id);
        let first = {
            let mut status = self.status.lock().expect("capture health poisoned");
            if status.reason.is_some() {
                false
            } else {
                status.reason = Some(reason.clone());
                status.last_reported_case = current_case;
                self.degraded.store(true, Ordering::Release);
                true
            }
        };
        if !first {
            return;
        }

        state.record_event_for_targets(self.proxy_error(reason), targets);
    }

    pub(super) fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub(super) fn reason(&self) -> Option<String> {
        self.status
            .lock()
            .expect("capture health poisoned")
            .reason
            .clone()
    }

    pub(super) async fn write_raw<W>(
        &self,
        state: &AppState,
        direction: RawTrafficDirection,
        writer: &mut W,
        bytes: &[u8],
    ) -> Result<u64>
    where
        W: AsyncWrite + Unpin,
    {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.note_activity(state, direction);
        writer.write_all(bytes).await?;
        Ok(bytes.len() as u64)
    }

    pub(super) async fn copy_raw<R, W>(
        &self,
        state: &AppState,
        direction: RawTrafficDirection,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut copied = 0_u64;
        let mut buffer = [0_u8; RAW_COPY_BUFFER_BYTES];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                return Ok(copied);
            }
            self.note_activity(state, direction);
            writer.write_all(&buffer[..read]).await?;
            copied += read as u64;
        }
    }

    fn note_activity(&self, state: &AppState, direction: RawTrafficDirection) {
        if direction != RawTrafficDirection::ClientToServer || !self.is_degraded() {
            return;
        }
        let targets = state.capture_dependency_targets();
        let Some(case_id) = targets.cases.first().map(|(case, _)| case.id) else {
            return;
        };
        let reason = {
            let mut status = self.status.lock().expect("capture health poisoned");
            if status.last_reported_case == Some(case_id) {
                return;
            }
            let Some(reason) = status.reason.clone() else {
                return;
            };
            status.last_reported_case = Some(case_id);
            reason
        };
        state.record_event_for_targets(self.proxy_error(reason), targets);
    }

    fn proxy_error(&self, error: String) -> RecorderEvent {
        RecorderEvent::ProxyError(ProxyErrorEvent {
            id: Uuid::new_v4(),
            connection_id: Some(self.connection_id),
            timestamp: Utc::now(),
            protocol: self.protocol.to_string(),
            client_addr: self.client_addr.clone(),
            target: Some(self.target.clone()),
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tempfile::{TempDir, tempdir};

    use crate::recorder::CaseContext;
    use crate::{AppConfig, AppState};

    use super::*;

    #[tokio::test]
    async fn degraded_connection_is_reported_once_for_each_case_with_client_activity() {
        let (state, _temp) = test_state().await;
        let connection_id = Uuid::new_v4();
        let health = ConnectionCaptureHealth::new(
            connection_id,
            "redis",
            Some("client:1234".to_string()),
            "redis.test:6379".to_string(),
        );
        let first_case = case("first");
        let first_guard = state.try_reserve_active_case(first_case.clone()).unwrap();
        state
            .activate_case_dependencies(&first_guard)
            .expect("first case dependencies should activate");

        health.activate(&state, "capture failed".to_string());
        let mut sink = tokio::io::sink();
        health
            .write_raw(
                &state,
                RawTrafficDirection::ClientToServer,
                &mut sink,
                b"first chunk",
            )
            .await
            .unwrap();
        health
            .write_raw(
                &state,
                RawTrafficDirection::ClientToServer,
                &mut sink,
                b"second chunk",
            )
            .await
            .unwrap();
        drop(first_guard);

        let second_case = case("second");
        let second_guard = state.try_reserve_active_case(second_case.clone()).unwrap();
        state
            .activate_case_dependencies(&second_guard)
            .expect("second case dependencies should activate");
        health
            .write_raw(
                &state,
                RawTrafficDirection::ClientToServer,
                &mut sink,
                b"third chunk",
            )
            .await
            .unwrap();

        for case in [&first_case, &second_case] {
            state
                .recorder()
                .flush_case_dependency_files(&state.recorder().case_staging_dir(case))
                .await
                .unwrap();
            let raw = tokio::fs::read_to_string(
                state
                    .recorder()
                    .case_staging_dir(case)
                    .join("dependencies.jsonl"),
            )
            .await
            .unwrap();
            let events = raw
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["event_type"], "proxy_error");
            assert_eq!(events[0]["connection_id"], connection_id.to_string());
            assert_eq!(events[0]["error"], "capture failed");
        }
    }

    fn case(name: &str) -> CaseContext {
        CaseContext {
            id: Uuid::new_v4(),
            rule_name: name.to_string(),
            uri_group: None,
        }
    }

    async fn test_state() -> (AppState, TempDir) {
        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();
        (state, temp)
    }
}
