//! Case admission, dependency observation and publication lifecycle wiring.

use crate::active_case::{DependencyDrainResult, DependencyTargets};
use crate::recorder::api_origin_observation::{ApiOriginScope, DependencyRequest};
use crate::recorder::readiness::PostReadyWaitOutcome;
use crate::recorder::{CaseContext, CaseInvalidation};
use crate::recording_control::RecordingListener;
use crate::{ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRejection, AppState};
use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tracing::{info, warn};
use uuid::Uuid;

impl AppState {
    pub(crate) fn configure_case_observation(
        &self,
        case_id: Uuid,
        method: &hyper::Method,
        uri: &hyper::Uri,
        body: &[u8],
        started: Instant,
        request_timeout: Duration,
    ) {
        let idle = Duration::from_millis(self.config().recording.api_origin_dependency_idle_ms);
        if idle.is_zero() {
            return;
        }
        if let Some(scope) = ApiOriginScope::for_primary(
            &self.config().process_owned_dependencies,
            method,
            uri,
            body,
        ) {
            self.inner.active_cases.configure_observation(
                case_id,
                scope,
                idle,
                started,
                request_timeout,
            );
            info!(%case_id, idle_ms = idle.as_millis(), "API-origin dependency observation enabled");
        }
    }

    pub(crate) fn capture_dependency_request(
        &self,
        request: DependencyRequest<'_>,
    ) -> DependencyTargets {
        self.inner
            .active_cases
            .current_targets_for_request(&request)
    }

    pub(crate) fn try_reserve_active_case(
        &self,
        case: CaseContext,
    ) -> Result<ActiveCaseGuard, ActiveCaseRejection> {
        self.inner.active_cases.try_reserve(case)
    }

    pub(crate) async fn close_bootstrap(&self, reason: &'static str) -> Result<bool> {
        let closed = self.inner.active_cases.close_bootstrap();
        if !closed {
            return Ok(false);
        }
        info!(reason, "bootstrap dependency window closed");
        self.seal_bootstrap_dependencies(reason).await?;
        if !self.inner.active_cases.enable_case_matching() {
            return Ok(false);
        }
        self.inner.recording_lifecycle.mark_source_ready();
        Ok(true)
    }

    pub(crate) async fn seal_bootstrap_dependencies(&self, reason: &'static str) -> Result<()> {
        if self.inner.active_cases.is_bootstrap_sealed() {
            return Ok(());
        }
        self.inner
            .active_cases
            .wait_for_bootstrap_dependencies()
            .await;
        if let Err(error) = self.recorder().seal_bootstrap_dependencies().await {
            self.inner.recording_lifecycle.mark_failed(&error);
            return Err(error).context("failed to seal bootstrap dependencies");
        }
        self.inner.active_cases.mark_bootstrap_sealed();
        info!(reason, "bootstrap dependencies sealed");
        Ok(())
    }

    pub(crate) fn activate_case_dependencies(
        &self,
        guard: &ActiveCaseGuard,
    ) -> Result<(), ActiveCaseActivationError> {
        guard.activate_dependencies()
    }

    pub(crate) fn is_bootstrap_open(&self) -> bool {
        self.inner.active_cases.is_bootstrap_open()
    }

    pub(crate) fn has_background_initial_loads(&self) -> bool {
        self.inner.process_owned_dependencies.has_initial_loads()
    }

    pub(crate) async fn wait_for_background_initial_loads(&self) -> Result<()> {
        self.inner
            .process_owned_dependencies
            .ensure_resources_resolved()?;
        self.inner
            .process_owned_dependencies
            .wait_for_initial_loads()
            .await;
        Ok(())
    }

    pub(crate) fn record_redis_cache_request(&self) {
        self.inner
            .process_owned_dependencies
            .record_redis_cache_request();
    }

    pub(crate) async fn wait_for_post_ready_admission(
        &self,
        ready_at: tokio::time::Instant,
    ) -> Result<PostReadyWaitOutcome> {
        let maximum_wait = self.config().recording.post_ready_max_wait();
        let maximum_deadline = ready_at + maximum_wait;
        if tokio::time::timeout_at(maximum_deadline, self.wait_for_background_initial_loads())
            .await
            .is_err()
        {
            return Ok(PostReadyWaitOutcome::MaximumWaitElapsed);
        }
        Ok(self
            .inner
            .process_owned_dependencies
            .wait_for_redis_cache_quiet_period(
                ready_at,
                self.config().recording.post_ready_quiet_period(),
                maximum_wait,
            )
            .await)
    }

    pub(crate) fn begin_case_quiescing(&self) -> bool {
        self.inner.active_cases.begin_quiescing()
    }

    pub(crate) fn recording_lifecycle_phase(&self) -> &'static str {
        if self.inner.active_cases.is_quiescing() {
            "quiescing"
        } else {
            "running"
        }
    }

    pub(crate) fn mark_recording_listener_ready(&self, listener: RecordingListener) {
        self.inner.recording_lifecycle.mark_listener_ready(listener);
    }

    pub(crate) async fn mark_recording_upstream_ready(
        &self,
        listener: RecordingListener,
        reason: &'static str,
    ) -> Result<bool> {
        if !self.inner.recording_lifecycle.mark_upstream_ready(listener) {
            return Ok(false);
        }
        let ready_at = tokio::time::Instant::now();
        if self.has_background_initial_loads()
            || !self.config().recording.post_ready_quiet_period().is_zero()
        {
            info!(
                reason,
                post_ready_quiet_ms = self
                    .config()
                    .recording
                    .post_ready_quiet_period()
                    .as_millis(),
                post_ready_max_wait_ms = self.config().recording.post_ready_max_wait_ms,
                waits_for_background_initial_load = self.has_background_initial_loads(),
                "all enabled upstreams ready; waiting for case admission prerequisites"
            );
        }
        let wait_outcome = self
            .wait_for_post_ready_admission(ready_at)
            .await
            .context("post-ready process-owned dependency observation failed with the source")?;
        if wait_outcome == PostReadyWaitOutcome::MaximumWaitElapsed {
            warn!(
                post_ready_max_wait_ms = self.config().recording.post_ready_max_wait_ms,
                "post-ready process-owned dependency observation reached its hard limit; continuing recording"
            );
        }
        self.close_bootstrap(reason).await
    }

    pub(crate) async fn wait_for_active_case_shutdown_drain(&self) -> bool {
        self.inner
            .active_cases
            .wait_for_no_active_case(Duration::from_millis(
                self.config().recording.shutdown_case_drain_timeout_ms,
            ))
            .await
    }

    pub(crate) fn active_case_invalidation(&self, case_id: Uuid) -> Option<CaseInvalidation> {
        self.inner.active_cases.invalidation_for(case_id)
    }

    pub(crate) fn invalidate_active_case(
        &self,
        case_id: Uuid,
        invalidation: CaseInvalidation,
    ) -> Option<CaseContext> {
        self.inner
            .active_cases
            .invalidate_case(case_id, invalidation)
    }

    pub(crate) async fn drain_active_case_dependencies(
        &self,
        case_id: Uuid,
    ) -> Option<CaseInvalidation> {
        let post_response_window = Duration::from_millis(
            self.config()
                .recording
                .case_dependency_post_response_window_ms,
        );
        let timeout =
            Duration::from_millis(self.config().recording.case_dependency_drain_timeout_ms);
        let result = self
            .inner
            .active_cases
            .drain_case_dependencies(case_id, post_response_window, timeout)
            .await;
        if let Some((case, mut report)) = self.inner.active_cases.observation_report(case_id) {
            let inventory_complete = report["inventory_complete"] == true;
            report["outcome"] = match result {
                DependencyDrainResult::Drained => "quiet",
                DependencyDrainResult::TimedOut => "dependency_drain_timeout",
                DependencyDrainResult::ObservationTimedOut => "request_deadline",
            }
            .into();
            if !inventory_complete {
                report["outcome"] = "inventory_limit".into();
            }
            if let Err(error) = self
                .recorder()
                .write_case_json(&case, "api-origin-observation.json", &report)
                .await
            {
                return Some(CaseInvalidation::new(
                    "recording_observation_failure",
                    format!("failed to persist API-origin observation: {error}"),
                ));
            }
            if !inventory_complete {
                self.begin_case_quiescing();
                return Some(CaseInvalidation::new(
                    "api_origin_observation_limit",
                    "API-origin selected dependency inventory exceeded 100000 exchanges; observation is incomplete",
                ));
            }
        }
        match result {
            DependencyDrainResult::Drained => None,
            DependencyDrainResult::ObservationTimedOut => Some(CaseInvalidation::new(
                "api_origin_observation_timeout",
                "API-origin dependency observation reached the absolute request deadline before selected traffic became quiet",
            )),
            DependencyDrainResult::TimedOut => {
                warn!(
                    case_id = %case_id,
                    post_response_window_ms = post_response_window.as_millis(),
                    timeout_ms = timeout.as_millis(),
                    "recording case in-flight dependency drain timed out"
                );
                Some(CaseInvalidation::new(
                    "dependency_drain_timeout",
                    format!(
                        "case dependencies accepted during the {} ms post-response window did not complete within {} ms after dependency admission closed",
                        post_response_window.as_millis(),
                        timeout.as_millis()
                    ),
                ))
            }
        }
    }

    pub(crate) fn capture_dependency_targets(&self) -> DependencyTargets {
        self.inner.active_cases.current_targets_for_event()
    }
}

#[cfg(test)]
mod tests;
