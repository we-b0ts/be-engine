//! Managed Target lifecycle markers for an event session.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use tokio::task::JoinHandle;

use super::super::{
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout},
    runtime, store,
};
use crate::{TargetImage, replay_timer::ManagedTimer};

pub(super) struct Target<'a> {
    pub(super) state: ActiveRunState,
    config: &'a ResolvedProjectConfig,
    layout: &'a RunLayout,
    image: TargetImage,
    timer: Option<&'a ManagedTimer>,
    ca: &'a Path,
    checks: Option<JoinHandle<Result<()>>>,
    stopping: Option<JoinHandle<(ActiveRunState, Result<()>)>>,
}

impl<'a> Target<'a> {
    pub(super) fn new(
        state: ActiveRunState,
        config: &'a ResolvedProjectConfig,
        layout: &'a RunLayout,
        image: TargetImage,
        timer: Option<&'a ManagedTimer>,
        ca: &'a Path,
    ) -> Self {
        Self {
            state,
            config,
            layout,
            image,
            timer,
            ca,
            checks: None,
            stopping: None,
        }
    }

    pub(super) async fn start(&mut self) -> Result<()> {
        runtime::start_target_with_replay_ca(
            self.config,
            self.layout,
            &mut self.state,
            &self.image,
            self.ca,
            self.timer,
        )
        .await
    }

    pub(super) fn ready(&mut self) {
        let (config, layout, state) =
            (self.config.clone(), self.layout.clone(), self.state.clone());
        let has_timer = self.timer.is_some();
        self.checks = Some(tokio::spawn(async move {
            runtime::verify_target_runtime_contract(&config, &layout, &state, has_timer).await
        }));
    }

    pub(super) async fn stop(&mut self) -> Result<()> {
        if let Some(checks) = self.checks.take() {
            checks
                .await
                .context("Target runtime verification task failed")??;
        }
        ensure!(
            self.stopping.is_none() && self.state.target_started,
            "invalid Target stop boundary"
        );
        let (layout, mut state) = (self.layout.clone(), self.state.clone());
        self.stopping = Some(tokio::spawn(async move {
            let result = runtime::stop_target_at_case_boundary(&layout, &mut state).await;
            (state, result)
        }));
        Ok(())
    }

    pub(super) async fn exited(&mut self, expected: Option<i32>) -> Result<()> {
        let stopping = self
            .stopping
            .as_mut()
            .context("recorded Source exit has no stop boundary")?;
        let (state, result) = stopping.await.context("Target stop task failed")?;
        self.stopping = None;
        self.state = state;
        result?;
        let path = self.layout.active_dir.join("reports/target-stop.json");
        let evidence: serde_json::Value = serde_json::from_slice(&tokio::fs::read(path).await?)?;
        let actual = evidence["exit_code"]
            .as_i64()
            .context("Target exit status is unavailable")?;
        // The recording controller requested the same normal SIGTERM shutdown.
        // Both an application exit code of zero and the delivered signal are
        // valid completions of that specific transport operation.
        let intentional_stop = matches!(expected, Some(0 | 143)) && matches!(actual, 0 | 143);
        let expected = i64::from(expected.context("recorded Source exit status is unavailable")?);
        ensure!(
            intentional_stop || actual == expected,
            "Target process exit status differs (expected {expected}, observed {actual})"
        );
        store::write_active(self.layout, &self.state)
    }

    pub(super) async fn stop_after_failure(&mut self) {
        if let Some(checks) = self.checks.take() {
            checks.abort();
        }
        if let Some(mut task) = self.stopping.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(10), &mut task).await {
                Ok(Ok((state, _))) => self.state = state,
                _ => task.abort(),
            }
        }
        // Keep interception installed until the failed Target has stopped.
        let replay_pid = self.state.replay_pid.take();
        runtime::best_effort_stop(self.config, self.layout, &mut self.state).await;
        self.state.replay_pid = replay_pid;
    }

    pub(super) async fn cleanup(mut self, replay: &mut tokio::process::Child) {
        runtime::stop_replay_process(&mut self.state, replay).await;
        let _ = store::write_active(self.layout, &self.state);
    }
}
