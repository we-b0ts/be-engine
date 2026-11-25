use super::*;
use crate::{CleanupFuture, ExecutionDriver, ExecutionFuture};

pub(super) struct ApplicationDriver<'a> {
    config: &'a ResolvedProjectConfig,
    layout: &'a RunLayout,
    inventory: &'a CaseGroupInventory,
    state: &'a mut ActiveRunState,
    finalization: crate::replay::FinalizationScope,
    target_image: Option<crate::TargetImage>,
    replay: Option<Child>,
    replay_ca: Option<PathBuf>,
    intentionally_incomplete: bool,
}

impl<'a> ApplicationDriver<'a> {
    pub(super) fn new(
        config: &'a ResolvedProjectConfig,
        layout: &'a RunLayout,
        inventory: &'a CaseGroupInventory,
        state: &'a mut ActiveRunState,
        finalization: crate::replay::FinalizationScope,
    ) -> Self {
        Self {
            config,
            layout,
            inventory,
            state,
            finalization,
            target_image: None,
            replay: None,
            replay_ca: None,
            intentionally_incomplete: false,
        }
    }
}

impl ExecutionDriver for ApplicationDriver<'_> {
    fn prepare(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            let config = self.config;
            let layout = self.layout;
            let state = &mut *self.state;
            timing_guard::freeze(config, &layout.target_root, state)?;
            store::write_active(layout, state)?;
            let _ = active_progress::write(layout, state, ActiveProgressPhase::PreparingIndex);
            let index_deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(config.replay_loading.index_timeout_seconds);
            crate::dependency_index::store::prepare_with_timeout(
                layout.case_source.clone(),
                config.replay_loading.index_timeout_seconds,
                crate::protocols::replay::source::validate_index_record,
            )
            .await
            .context("Replay dependency index preparation failed")?;
            // Cold Source analysis belongs to the index budget, not listener readiness
            // or per-request execution. The Replay process imports the resulting cache.
            let source = layout.case_source.clone();
            let rules = crate::config::SourceTrafficPolicyConfig::load_with_fingerprints(
                &config.replay_policy,
            )?
            .0
            .process_owned_dependencies;
            let preparation =
                tokio::task::spawn_blocking(move || crate::api_trigger::prepare(&source, &rules));
            tokio::time::timeout_at(index_deadline, preparation)
                .await
                .context("MySQL Source ownership preparation exceeded the dependency index budget")?
                .context("MySQL Source ownership preparation task failed")??;
            let _ = active_progress::write(layout, state, ActiveProgressPhase::Building);
            self.target_image = Some(build_target_image(config, layout, false).await?);
            timing_guard::before_spawn(config, &layout.target_root, state)?;
            Ok(())
        })
    }

    fn spawn_replay(&mut self) -> Result<()> {
        let replay = spawn_replay(self.config, self.layout, self.inventory, self.state)
            .context("Replay startup failed")?;
        self.state.replay_pid = replay.id();
        self.replay = Some(replay);
        Ok(())
    }

    fn wait_ready(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            let config = self.config;
            let layout = self.layout;
            let state = &mut *self.state;
            let replay = self
                .replay
                .as_mut()
                .context("Replay process was not started")?;
            store::write_active(layout, state)?;
            let _ = active_progress::write(layout, state, ActiveProgressPhase::PreparingReplay);
            let ready = async {
                tokio::select! {
                    ready = wait_for_replay_ready(state, config.replay_startup_timeout) => {
                        ready.context("replay server did not become ready; project.replay.startup_timeout_seconds controls the readiness budget independently of dependency_loading.index_timeout_seconds and case_timeout_seconds")
                    }
                    status = replay.wait() => {
                        let status = status.context("failed to wait for replay process during startup")?;
                        bail!("{}", super::super::runtime::replay_startup_failure(layout, status).await);
                    }
                }
            }
            .await
            .context("Replay startup failed")?;
            super::super::runtime::validate_replay_case_selection(&ready, state)
                .context("Replay startup failed")?;
            state.session_id = ready
                .pointer("/session/session_id")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned);
            ensure!(
                state.session_id.is_some(),
                "replay session has no session id"
            );
            self.replay_ca = Some(replay_ca_cert_path(&ready)?);
            store::write_active(layout, state)?;

            Ok(())
        })
    }

    fn start_target(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            let config = self.config;
            let layout = self.layout;
            let state = &mut *self.state;
            let _ = active_progress::write(layout, state, ActiveProgressPhase::StartingTarget);
            start_target_with_replay_ca(
                config,
                layout,
                state,
                self.target_image
                    .as_ref()
                    .context("Target image was not prepared")?,
                self.replay_ca
                    .as_ref()
                    .context("Replay CA was not prepared")?,
                None,
            )
            .await?;
            super::super::primary_driver::wait_until_ready(config).await?;
            verify_target_runtime_contract(config, layout, state, false)
                .await
                .context("target Replay runtime contract failed")?;

            Ok(())
        })
    }

    fn execute_cases(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            let config = self.config;
            let layout = self.layout;
            let state = &mut *self.state;
            let case_runtime = CaseExecutionRuntime {
                request_rules: Arc::new(crate::request_rules::RequestRuleRuntime::load(
                    &layout.target_root,
                    &config.replay_policy,
                )?),
                response_assertions: config
                    .runner_owned_response_assertions
                    .then(|| ResponseAssertionRuntime::load(&config.replay_policy))
                    .transpose()?,
            };

            super::super::case_sequence::execute(config, layout, state, &case_runtime).await?;

            self.intentionally_incomplete = state
                .cases
                .iter()
                .any(|case| case.status == CaseStatus::Pending);

            Ok(())
        })
    }

    fn stop_target(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            let layout = self.layout;
            let state = &mut *self.state;
            if state.target_started {
                stop_target_runtime(layout, state).await?;
            }
            state.status = RunStatus::Finalizing;
            store::write_active(layout, state)?;
            let _ = active_progress::write(layout, state, ActiveProgressPhase::GeneratingEvidence);

            Ok(())
        })
    }

    fn finalize(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            finalize_replay(self.state, self.intentionally_incomplete, self.finalization).await?;
            Ok(())
        })
    }

    fn finish(&mut self) -> ExecutionFuture<'_, ()> {
        Box::pin(async move {
            let config = self.config;
            let layout = self.layout;
            let state = &mut *self.state;
            let inventory = self.inventory;
            let replay = self
                .replay
                .as_mut()
                .context("Replay process was not started")?;
            let _ = active_progress::write(layout, state, ActiveProgressPhase::Finalizing);
            wait_for_replay(replay).await?;
            state.replay_pid = None;
            build_final_evidence(config, layout, inventory, state)?;
            super::super::batch_evidence::validate_executed_identity(&layout.target_root, state)?;
            if state.target_started {
                best_effort_stop(config, layout, state).await;
            }
            state.finished_at = Some(Utc::now());
            state.status = if state
                .cases
                .iter()
                .all(|case| case.status == CaseStatus::Passed)
                && state.replay_finalized
                && state.aggregate_complete
                && state.aggregate_clean
                && state.apis.iter().all(|api| api.complete_pass)
                && state.errors.is_empty()
            {
                RunStatus::Successful
            } else {
                RunStatus::Failed
            };
            Ok(())
        })
    }

    fn interrupt(&mut self) -> CleanupFuture<'_> {
        Box::pin(async move {
            let config = self.config;
            let layout = self.layout;
            let state = &mut *self.state;
            let inventory = self.inventory;
            if let Err(error) =
                super::super::interrupted_evidence::preserve(config, layout, inventory, state).await
            {
                state.push_error(format!(
                    "interrupted Replay diagnostics could not be preserved: {error:#}"
                ));
            }
            if let Some(replay) = self.replay.as_mut() {
                stop_replay_process(state, replay).await;
            }
        })
    }
}
