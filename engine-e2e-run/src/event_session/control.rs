//! Bounded control exchange for globally ordered primary events.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use super::E2eEventSessionProgress;
use crate::{
    replay::control::MAX_CONTROL_BYTES,
    value_contract::{identities::IdentityPair, response_constraints::MAX_PAIRS},
};

const REPLY_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct SessionControl {
    socket: std::path::PathBuf,
}

impl SessionControl {
    pub(super) async fn from_session(path: &Path) -> Result<Self> {
        let raw = tokio::fs::read(path)
            .await
            .context("read Replay session identity")?;
        let session: Value = serde_json::from_slice(&raw)?;
        let socket = session["control_socket"]
            .as_str()
            .map(Path::new)
            .filter(|socket| socket.is_absolute())
            .context("Replay session has no absolute control socket")?;
        Ok(Self {
            socket: socket.to_owned(),
        })
    }

    pub(super) async fn wait(&self, sequence: u64) -> Result<()> {
        // Replay enforces a rolling no-progress deadline while the driver
        // independently checks control socket health with session_status.
        self.request(json!({"command":"session_wait","sequence":sequence}), None)
            .await?;
        Ok(())
    }

    pub(super) async fn commit(&self, sequence: u64) -> Result<()> {
        self.commit_with_response_identities(sequence, &[]).await
    }

    pub(super) async fn commit_with_response_identities(
        &self,
        sequence: u64,
        pairs: &[IdentityPair],
    ) -> Result<()> {
        let mut request = json!({"command":"session_commit","sequence":sequence});
        if !pairs.is_empty() {
            ensure!(
                pairs.len() <= MAX_PAIRS,
                "response identity constraint bound exceeded"
            );
            request["identity_pairs"] = serde_json::to_value(pairs)?;
        }
        self.request(request, Some(COMMAND_TIMEOUT)).await?;
        Ok(())
    }

    pub(super) async fn fail(&self, sequence: u64, reason: &str) -> Result<()> {
        let reply = self
            .exchange(
                json!({"command":"session_fail","sequence":sequence,"reason":reason}),
                Some(COMMAND_TIMEOUT),
            )
            .await?;
        ensure!(
            reply
                .pointer("/session_events/failure")
                .is_some_and(|failure| !failure.is_null()),
            "Replay did not retain the event failure"
        );
        Ok(())
    }

    pub(super) async fn status(&self) -> Result<E2eEventSessionProgress> {
        let reply = self
            .exchange(json!({"command":"session_status"}), Some(COMMAND_TIMEOUT))
            .await?;
        Ok(serde_json::from_value(reply["session_events"].clone())?)
    }

    async fn request(&self, request: Value, timeout: Option<Duration>) -> Result<Value> {
        let reply = self.exchange(request, timeout).await?;
        ensure!(
            reply["ok"] == true,
            "{}",
            reply["error"]
                .as_str()
                .unwrap_or("Replay event control command was rejected")
        );
        Ok(reply)
    }

    async fn exchange(&self, request: Value, timeout: Option<Duration>) -> Result<Value> {
        let command = request["command"]
            .as_str()
            .expect("internal Replay command");
        let started = tokio::time::Instant::now();
        let stream = tokio::time::timeout_at(started + COMMAND_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.socket).await?;
            let mut frame = serde_json::to_vec(&request)?;
            ensure!(
                frame.len() < MAX_CONTROL_BYTES,
                "Replay control request exceeds its limit"
            );
            frame.push(b'\n');
            stream.write_all(&frame).await?;
            Ok::<_, anyhow::Error>(stream)
        })
        .await
        .with_context(|| format!("Replay event control send timed out ({command})"))??;
        let receive = async {
            let mut reply = Vec::new();
            BufReader::new(stream)
                .take((REPLY_LIMIT + 1) as u64)
                .read_until(b'\n', &mut reply)
                .await?;
            ensure!(
                reply.len() <= REPLY_LIMIT,
                "Replay control reply exceeds its limit"
            );
            let reply: Value = serde_json::from_slice(&reply)?;
            Ok(reply)
        };
        match timeout {
            Some(timeout) => tokio::time::timeout_at(started + timeout, receive)
                .await
                .with_context(|| format!("Replay event control timed out ({command})"))?,
            None => receive.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_status_preserves_streaming_totals_and_failure_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let driver = tokio::spawn(async move {
            let control = SessionControl { socket };
            for (total, complete, has_failure) in [
                (None, false, false),
                (None, false, true),
                (Some(2), true, false),
            ] {
                let status = control.status().await.unwrap();
                assert_eq!(status.total, total);
                assert_eq!(status.complete, complete);
                assert_eq!(status.failure.is_some(), has_failure);
                assert_eq!(status.matched, 2);
            }
        });
        for (total, complete, failure) in [
            (None, false, None),
            (
                None,
                false,
                Some(json!({"reported_sequence": 10, "reason": "invalid Source row"})),
            ),
            (Some(2), true, None),
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            stream.read_line(&mut request).await.unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&request).unwrap(),
                json!({"command":"session_status"})
            );
            let mut reply = serde_json::to_vec(&json!({
                "ok": failure.is_none(),
                "session_events": {
                    "matched": 2, "total": total, "complete": complete, "expected": null,
                    "last_sequence": 9, "failure": failure,
                },
            }))
            .unwrap();
            reply.push(b'\n');
            stream.get_mut().write_all(&reply).await.unwrap();
        }
        driver.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn session_wait_allows_replay_to_keep_advancing_before_the_next_driver_event() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let driver = tokio::spawn(async move { SessionControl { socket }.wait(50).await });

        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut frame = String::new();
        stream.read_line(&mut frame).await.unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&frame).unwrap(),
            json!({"command":"session_wait","sequence":50})
        );
        tokio::time::advance(COMMAND_TIMEOUT * 2).await;
        assert!(!driver.is_finished());
        stream
            .get_mut()
            .write_all(b"{\"ok\":true}\n")
            .await
            .unwrap();
        driver.await.unwrap().unwrap();
    }
}
