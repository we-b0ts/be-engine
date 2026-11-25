use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinSet;
use tokio::time::Sleep;
use tracing::{info, warn};

use crate::network_probe::{CASE_LIMIT_SHUTDOWN_GRACE, PreflightProbeKind};
use crate::recording_completion::RecordingCompletionReason;
use crate::recording_control::RecordingControlServer;
use crate::{AppState, dns_mock, gateway, proxy, tcp_gateway, udp_gateway};

impl AppState {
    pub async fn run(self) -> Result<()> {
        self.run_with_control_socket(None).await
    }

    async fn quiesce_recording(&self, reason: RecordingCompletionReason, trigger: &'static str) {
        let newly_quiescing = self.begin_case_quiescing();
        self.inner.recording_lifecycle.mark_stopping();
        // Persistence can yield to the last Case publisher. Its shutdown
        // association must already be frozen before that guard is released.
        self.recorder().set_completion_reason(reason).await;
        let timeout_ms = self.config().recording.shutdown_case_drain_timeout_ms;
        info!(
            trigger,
            newly_quiescing, timeout_ms, "recording stopping; draining active case"
        );
        if self.wait_for_active_case_shutdown_drain().await {
            info!(trigger, "active recording case shutdown drain completed");
        } else {
            warn!(
                trigger,
                timeout_ms, "active recording case shutdown drain timed out"
            );
        }
    }

    pub async fn run_with_control_socket(self, control_socket: Option<PathBuf>) -> Result<()> {
        self.run_until(control_socket, shutdown_signal()).await
    }

    /// Runs until the caller requests shutdown, then drains and finalizes cases.
    pub async fn run_until<F>(self, control_socket: Option<PathBuf>, shutdown: F) -> Result<()>
    where
        F: std::future::Future<Output = Result<()>>,
    {
        anyhow::ensure!(
            !self.session_events(),
            "session event recording requires a managed Source process through traffic-e2e record"
        );
        self.run_until_completion(control_socket, async {
            shutdown
                .await
                .map(|()| RecordingCompletionReason::ShutdownSignal)
        })
        .await
    }

    /// Retains the supervisor's stop cause through the same drain/finalization path.
    pub async fn run_until_completion<F>(
        self,
        control_socket: Option<PathBuf>,
        shutdown: F,
    ) -> Result<()>
    where
        F: std::future::Future<Output = Result<RecordingCompletionReason>>,
    {
        anyhow::ensure!(
            self.config().upstream_routes.is_empty()
                || self.inner.recording_upstreams.get().is_some(),
            "Kubernetes upstream routes must be prepared by traffic-e2e record before starting Recorder"
        );
        tokio::pin!(shutdown);
        let control_server = match control_socket {
            Some(path) => Some(
                RecordingControlServer::start(self.inner.recording_lifecycle.clone(), path).await?,
            ),
            None => None,
        };
        let mut tasks = JoinSet::new();

        if self.config().http.enabled {
            let http_state = self.clone();
            tasks.spawn(async move { proxy::http::run(http_state).await });
        }

        if self.config().dns_mock.enabled {
            let dns_state = self.clone();
            tasks.spawn(async move { dns_mock::run(dns_state).await });
        }

        if self.config().tcp_gateway.enabled {
            let tcp_gateway_state = self.clone();
            tasks.spawn(async move { tcp_gateway::run(tcp_gateway_state).await });
        }

        if self.config().udp_gateway.enabled {
            let udp_gateway_state = self.clone();
            tasks.spawn(async move { udp_gateway::run(udp_gateway_state).await });
        }

        if self.config().http_gateway.enabled {
            let gateway_state = self.clone();
            tasks.spawn(async move { gateway::http::run(gateway_state).await });
        }

        if self.config().mysql.enabled {
            let mysql_state = self.clone();
            let routes = self
                .config()
                .mysql
                .effective_routes()
                .into_iter()
                .map(|route| {
                    Ok(crate::recorder::native::listener::Route {
                        listen: route.listen,
                        endpoint: traffic_protocol::connection::endpoint_from_addr(&route.upstream)
                            .context("configured recording endpoint requires a host and port")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            tasks.spawn(async move {
                crate::recorder::native::listener::run(
                    mysql_state,
                    crate::protocols::DependencyProtocol::Mysql,
                    routes,
                    crate::recording_control::RecordingListener::Mysql,
                )
                .await
            });
        }

        info!(
            access_policy = self.config().recording.access_policy.as_str(),
            access_rules = self.config().recording.access_rules.len(),
            http_enabled = self.config().http.enabled,
            http_listen = %self.config().http.listen,
            dns_mock_enabled = self.config().dns_mock.enabled,
            tcp_gateway_enabled = self.config().tcp_gateway.enabled,
            udp_gateway_enabled = self.config().udp_gateway.enabled,
            http_gateway_enabled = self.config().http_gateway.enabled,
            mysql_enabled = self.config().mysql.enabled,
            "traffic recorder proxy started"
        );

        let mut registry_flush_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + dns_mock::REGISTRY_FLUSH_INTERVAL,
            dns_mock::REGISTRY_FLUSH_INTERVAL,
        );
        registry_flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let case_limit_completion = self.recorder().wait_for_explicit_api_case_limit();
        tokio::pin!(case_limit_completion);
        let mut case_limit_grace = None;
        let run_result = loop {
            tokio::select! {
                result = &mut shutdown => {
                    let reason = match result {
                        Ok(reason) => reason,
                        Err(error) => break Err(error),
                    };
                    self.quiesce_recording(reason, reason.as_str()).await;
                    break Ok(());
                }
                _ = &mut case_limit_completion, if case_limit_grace.is_none() => {
                    if let Some((probe_kind, grace)) =
                        preflight_case_limit_shutdown_grace(self.inner.preflight_probe)
                    {
                        info!(
                            probe_kind = probe_kind.matched_by(),
                            grace_ms = grace.as_millis(),
                            "preflight case limit reached; keeping Recorder available for the fixed probe grace period"
                        );
                        case_limit_grace = Some(Box::pin(tokio::time::sleep(grace)));
                        continue;
                    }
                    self.quiesce_recording(RecordingCompletionReason::PerApiCaseLimitReached, "per_api_case_limit_reached").await;
                    break Ok(());
                }
                _ = wait_for_optional_sleep(&mut case_limit_grace) => {
                    self.quiesce_recording(RecordingCompletionReason::PerApiCaseLimitReached, "preflight_case_limit_grace_elapsed").await;
                    break Ok(());
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let Some(joined) = joined else {
                        continue;
                    };
                    break match joined {
                        Ok(result) => result,
                        Err(error) => Err(error).context("proxy task panicked"),
                    };
                }
                _ = registry_flush_interval.tick() => {
                    match self.dns_registry().flush_if_dirty().await {
                        Ok(true) => info!("flushed fake DNS registry"),
                        Ok(false) => {}
                        Err(error) => {
                            warn!(
                                error = %error,
                                "failed to flush fake DNS registry; pending updates will be retried"
                            );
                        }
                    }
                }
            }
        };
        if let Err(error) = &run_result {
            self.inner.recording_lifecycle.mark_failed(error);
        }
        let runtime_succeeded = run_result.is_ok();

        tasks.abort_all();
        while let Some(joined) = tasks.join_next().await {
            if let Err(error) = joined
                && !error.is_cancelled()
            {
                warn!(error = %error, "proxy task failed while shutting down");
            }
        }
        self.kubectl_proxy_manager().shutdown().await;
        let capture_complete = self.close_dependency_capture().await;
        let finish_run_result = self
            .recorder()
            .finish_run_after_runtime(runtime_succeeded && capture_complete)
            .await
            .context("failed to finalize recording run");
        let registry_flush_result = self
            .dns_registry()
            .flush_if_dirty()
            .await
            .context("failed to flush fake DNS registry during shutdown");

        let result = async {
            let has_failed_cases = finish_run_result?;
            if has_failed_cases {
                warn!(
                    "recording run finalized with failed cases; published cases remain available"
                );
            }
            run_result?;
            registry_flush_result?;
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            self.inner.recording_lifecycle.mark_failed(error);
        }
        let control_result = match control_server {
            Some(server) => server.shutdown().await,
            None => Ok(()),
        };
        result.and(control_result)
    }
}

fn preflight_case_limit_shutdown_grace(
    preflight_probe: Option<PreflightProbeKind>,
) -> Option<(PreflightProbeKind, Duration)> {
    preflight_probe.map(|kind| (kind, CASE_LIMIT_SHUTDOWN_GRACE))
}

async fn wait_for_optional_sleep(sleep: &mut Option<Pin<Box<Sleep>>>) {
    match sleep {
        Some(sleep) => sleep.await,
        None => std::future::pending().await,
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn runtime_fixture(explicit_case_limit: bool) -> (tempfile::TempDir, AppState) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempfile::tempdir().unwrap();
        let mut config = crate::AppConfig::default();
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.encrypt_request_headers.clear();
        config.dns_mock.registry_path = temp.path().join("fake-dns.json");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        config.http_gateway.rules = vec![crate::HttpGatewayRuleConfig {
            path_prefixes: vec!["/".into()],
            ..Default::default()
        }];
        let apis = if explicit_case_limit {
            config.http_gateway.per_api_case_limits.default = 0;
            vec!["GET /disabled".parse().unwrap()]
        } else {
            Vec::new()
        };
        let state = AppState::new_with_recording_apis(config, None, apis)
            .await
            .unwrap();
        (temp, state)
    }

    #[tokio::test]
    async fn shutdown_causes_remain_distinct_in_finalized_manifest() {
        for (reason, expected) in [
            (RecordingCompletionReason::ShutdownSignal, "shutdown_signal"),
            (
                RecordingCompletionReason::SourceIsolationRequired,
                "source_isolation_required",
            ),
            (
                RecordingCompletionReason::SocketioCloseTailLimit,
                "socketio_close_tail_limit",
            ),
            (
                RecordingCompletionReason::PerApiCaseLimitReached,
                "per_api_case_limit_reached",
            ),
        ] {
            let (_temp, state) =
                runtime_fixture(reason == RecordingCompletionReason::PerApiCaseLimitReached).await;
            let run = match reason {
                RecordingCompletionReason::ShutdownSignal => {
                    // Preserve the public unit-valued shutdown API.
                    state
                        .clone()
                        .run_until(None, std::future::ready(Ok(())))
                        .await
                }
                RecordingCompletionReason::SourceIsolationRequired
                | RecordingCompletionReason::SocketioCloseTailLimit => {
                    state
                        .clone()
                        .run_until_completion(None, std::future::ready(Ok(reason)))
                        .await
                }
                RecordingCompletionReason::PerApiCaseLimitReached => {
                    state
                        .clone()
                        .run_until_completion(None, std::future::pending())
                        .await
                }
            };
            run.unwrap();
            let report: serde_json::Value = serde_json::from_slice(
                &std::fs::read(state.recorder().run_dir.join("recording-run.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(report["status"], "completed");
            assert_eq!(report["completion_reason"], expected);
        }
    }

    #[tokio::test]
    async fn shutdown_freezes_last_failed_case_before_waiting_for_the_manifest_lock() {
        let (_temp, state) = runtime_fixture(false).await;
        state.close_bootstrap("ready").await.unwrap();
        let case = crate::recorder::CaseContext {
            id: uuid::Uuid::new_v4(),
            rule_name: "failed".into(),
            uri_group: None,
        };
        let guard = state.try_reserve_active_case(case.clone()).unwrap();
        guard.activate_dependencies().unwrap();
        state.inner.active_cases.invalidate_case(
            case.id,
            crate::recorder::CaseInvalidation::new("original_failure", "incomplete primary"),
        );
        let manifest = state.recorder().run_state.lock().await;
        let mut shutdown = Box::pin(state.clone().run_until_completion(
            None,
            std::future::ready(Ok(RecordingCompletionReason::ShutdownSignal)),
        ));
        assert!(futures_util::poll!(&mut shutdown).is_pending());
        let before_release = state.inner.active_cases.current_targets_for_event();
        assert_eq!(
            before_release.phase,
            crate::dependency::observation::CapturePhase::Shutdown
        );
        assert_eq!(before_release.shutdown_case_id, Some(case.id));
        drop(before_release);
        drop(guard);
        let after_release = state.inner.active_cases.current_targets_for_event();
        assert!(after_release.cases.is_empty());
        assert_eq!(after_release.shutdown_case_id, Some(case.id));
        drop(manifest);
        shutdown.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_failure_remains_a_failed_manifest_without_a_success_reason() {
        let (_temp, state) = runtime_fixture(false).await;
        let error = state
            .clone()
            .run_until_completion(
                None,
                std::future::ready(Err(anyhow::anyhow!("supervisor failed"))),
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "supervisor failed");
        let report: serde_json::Value = serde_json::from_slice(
            &std::fs::read(state.recorder().run_dir.join("recording-run.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(report["status"], "failed");
        assert!(report["completion_reason"].is_null());
    }

    #[test]
    fn preflight_probe_adds_a_fixed_case_limit_shutdown_grace() {
        assert_eq!(
            preflight_case_limit_shutdown_grace(Some(PreflightProbeKind::JavaTruststore)),
            Some((PreflightProbeKind::JavaTruststore, Duration::from_secs(15)))
        );
        assert_eq!(preflight_case_limit_shutdown_grace(None), None);
    }
}
