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
use crate::{AppState, dns_mock, gateway, proxy, recorder, tcp_gateway, udp_gateway};

impl AppState {
    pub async fn run(self) -> Result<()> {
        self.run_with_control_socket(None).await
    }

    async fn quiesce_recording(&self, trigger: &'static str) {
        self.inner.recording_lifecycle.mark_stopping();
        let newly_quiescing = self.begin_case_quiescing();
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

        if self.config().motan_gateway.enabled {
            let gateway_state = self.clone();
            tasks.spawn(async move { gateway::motan::run(gateway_state).await });
        }

        if self.config().mysql.enabled {
            let mysql_state = self.clone();
            tasks.spawn(async move { recorder::mysql::run(mysql_state).await });
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
            motan_gateway_enabled = self.config().motan_gateway.enabled,
            mysql_enabled = self.config().mysql.enabled,
            "traffic recorder proxy started"
        );

        let mut registry_flush_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + dns_mock::REGISTRY_FLUSH_INTERVAL,
            dns_mock::REGISTRY_FLUSH_INTERVAL,
        );
        registry_flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);
        let case_limit_completion = self.recorder().wait_for_explicit_api_case_limit();
        tokio::pin!(case_limit_completion);
        let mut case_limit_grace = None;
        let run_result = loop {
            tokio::select! {
                result = &mut shutdown => {
                    if let Err(error) = result {
                        break Err(error);
                    }
                    self.recorder()
                        .set_completion_reason(RecordingCompletionReason::ShutdownSignal)
                        .await;
                    self.quiesce_recording("shutdown_signal").await;
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
                    self.recorder()
                        .set_completion_reason(
                            RecordingCompletionReason::PerApiCaseLimitReached,
                        )
                        .await;
                    self.quiesce_recording("per_api_case_limit_reached").await;
                    break Ok(());
                }
                _ = wait_for_optional_sleep(&mut case_limit_grace) => {
                    self.recorder()
                        .set_completion_reason(
                            RecordingCompletionReason::PerApiCaseLimitReached,
                        )
                        .await;
                    self.quiesce_recording("preflight_case_limit_grace_elapsed").await;
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
        let finish_run_result = self
            .recorder()
            .finish_run_after_runtime(runtime_succeeded)
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

    #[test]
    fn preflight_probe_adds_a_fixed_case_limit_shutdown_grace() {
        assert_eq!(
            preflight_case_limit_shutdown_grace(Some(PreflightProbeKind::JavaTruststore)),
            Some((PreflightProbeKind::JavaTruststore, Duration::from_secs(15)))
        );
        assert_eq!(preflight_case_limit_shutdown_grace(None), None);
    }
}
