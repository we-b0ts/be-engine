//! Bounded control exchange for globally ordered primary events.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use super::E2eEventSessionProgress;

const FRAME_LIMIT: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct SessionControl {
    socket: std::path::PathBuf,
    wait_timeout: Duration,
}

impl SessionControl {
    pub(super) async fn from_session(path: &Path, wait_timeout: Duration) -> Result<Self> {
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
            wait_timeout,
        })
    }

    pub(super) async fn wait(&self, sequence: u64) -> Result<()> {
        self.request(
            json!({"command":"session_wait","sequence":sequence}),
            self.wait_timeout,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn commit(&self, sequence: u64) -> Result<()> {
        self.request(
            json!({"command":"session_commit","sequence":sequence}),
            COMMAND_TIMEOUT,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn fail(&self, sequence: u64, reason: &str) -> Result<()> {
        let reply = self
            .exchange(
                json!({"command":"session_fail","sequence":sequence,"reason":reason}),
                COMMAND_TIMEOUT,
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
            .exchange(json!({"command":"session_status"}), COMMAND_TIMEOUT)
            .await?;
        Ok(serde_json::from_value(reply["session_events"].clone())?)
    }

    async fn request(&self, request: Value, timeout: Duration) -> Result<Value> {
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

    async fn exchange(&self, request: Value, timeout: Duration) -> Result<Value> {
        let command = request["command"]
            .as_str()
            .expect("internal Replay command");
        tokio::time::timeout(timeout, async {
            let mut stream = UnixStream::connect(&self.socket).await?;
            let mut frame = serde_json::to_vec(&request)?;
            ensure!(
                frame.len() < FRAME_LIMIT,
                "Replay control request exceeds its limit"
            );
            frame.push(b'\n');
            stream.write_all(&frame).await?;
            let mut reply = Vec::new();
            BufReader::new(stream)
                .take((FRAME_LIMIT + 1) as u64)
                .read_until(b'\n', &mut reply)
                .await?;
            ensure!(
                reply.len() <= FRAME_LIMIT,
                "Replay control reply exceeds its limit"
            );
            let reply: Value = serde_json::from_slice(&reply)?;
            Ok(reply)
        })
        .await
        .with_context(|| format!("Replay event control timed out ({command})"))?
    }
}
