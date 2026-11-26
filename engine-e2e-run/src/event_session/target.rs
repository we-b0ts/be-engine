//! Managed Target lifecycle markers for an event session.

use std::path::Path;

use anyhow::{Context, Result, ensure};
use tokio::task::JoinHandle;
use traffic_model::session::SIGKILL_EXIT_STATUS;

use super::super::{
    model::{ActiveRunState, ResolvedProjectConfig, RunLayout},
    runtime, store,
};
use crate::{TargetImage, replay_timer::ManagedTimer};

const SIGTERM_EXIT_STATUS: i32 = 128 + libc::SIGTERM;

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

    pub(super) async fn exited(
        &mut self,
        expected: Option<i32>,
        forced_by_recorder: bool,
    ) -> Result<()> {
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
        verify_exit_status(
            expected,
            forced_by_recorder,
            actual,
            evidence["running_before_stop"].as_bool(),
        )?;
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

fn verify_exit_status(
    expected: Option<i32>,
    forced_by_recorder: bool,
    actual: i64,
    running_before_stop: Option<bool>,
) -> Result<()> {
    let expected = expected.context("recorded Source exit status is unavailable")?;
    let stopped_after_sigterm = actual == 0 || actual == i64::from(SIGTERM_EXIT_STATUS);
    if forced_by_recorder {
        ensure!(
            expected == SIGKILL_EXIT_STATUS,
            "invalid Recorder-forced Source exit status {expected}"
        );
        ensure!(
            running_before_stop == Some(true),
            "Target was not observed running before the requested stop"
        );
        // The Source SIGKILL was Recorder cleanup after its requested stop.
        // Accept a Target that finished its own requested SIGTERM stop.
        ensure!(
            stopped_after_sigterm,
            "Target did not complete the requested stop (expected 0 or {SIGTERM_EXIT_STATUS}, observed {actual})"
        );
        return Ok(());
    }
    ensure!(
        (matches!(expected, 0 | SIGTERM_EXIT_STATUS) && stopped_after_sigterm)
            || actual == i64::from(expected),
        "Target process exit status differs (expected {expected}, observed {actual})"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_forced_source_stop_accepts_a_normal_target_exit() {
        for actual in [0, i64::from(SIGTERM_EXIT_STATUS)] {
            assert!(
                verify_exit_status(Some(SIGKILL_EXIT_STATUS), true, actual, Some(true)).is_ok()
            );
        }
        for actual in [1, i64::from(SIGKILL_EXIT_STATUS)] {
            assert!(
                verify_exit_status(Some(SIGKILL_EXIT_STATUS), true, actual, Some(true)).is_err()
            );
        }
        for expected in [None, Some(0), Some(SIGTERM_EXIT_STATUS)] {
            assert!(verify_exit_status(expected, true, 0, Some(true)).is_err());
        }
        for running_before_stop in [None, Some(false)] {
            assert!(
                verify_exit_status(Some(SIGKILL_EXIT_STATUS), true, 0, running_before_stop)
                    .is_err()
            );
        }
    }

    #[test]
    fn unmarked_source_exit_preserves_existing_status_matching() {
        assert!(verify_exit_status(Some(0), false, i64::from(SIGTERM_EXIT_STATUS), None).is_ok());
        assert!(verify_exit_status(Some(SIGTERM_EXIT_STATUS), false, 0, None).is_ok());
        assert!(verify_exit_status(Some(0), false, i64::from(SIGKILL_EXIT_STATUS), None).is_err());
        assert!(verify_exit_status(Some(SIGKILL_EXIT_STATUS), false, 0, None).is_err());
        assert!(
            verify_exit_status(
                Some(SIGKILL_EXIT_STATUS),
                false,
                i64::from(SIGKILL_EXIT_STATUS),
                None
            )
            .is_ok()
        );
        assert!(verify_exit_status(Some(2), false, 2, None).is_ok());
        assert!(verify_exit_status(Some(2), false, 3, None).is_err());
    }
}
