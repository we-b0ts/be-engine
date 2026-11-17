//! Persistent backend rewrite coordination over engine services.
#[cfg(test)]
use traffic_engine::test_support;
use traffic_engine::*;
use traffic_engine::{
    api_trigger, attribution_defaults, build_info, case_group, config, dependency,
    dependency_index, e2e_run, engine_binary, execution_identity, http, interaction,
    internal_runtime, path_pattern, policy_evidence, primary_protocol, recorder, recording_api,
    replay, repository, request_headers, source_snapshot, startup, value_codec, value_contract,
    value_extensions,
};
use traffic_engine::{json_value, verification_progress};
mod rewrite;
pub use rewrite::*;

/// Bind this workflow owner to engine operations in the composing process.
pub fn initialize() {
    traffic_engine::coordination::initialize(|| std::sync::Arc::new(WorkflowCoordinator));
}

struct WorkflowCoordinator;

impl traffic_engine::coordination::Coordinator for WorkflowCoordinator {
    fn freeze(
        &self,
        target: Option<&std::path::Path>,
        source: &std::path::Path,
        run: &str,
    ) -> anyhow::Result<traffic_engine::coordination::FrozenAttribution> {
        rewrite::freeze_dependency_attribution(target, source, run)
    }
    fn identity(
        &self,
        target: &std::path::Path,
        source: Option<&std::path::Path>,
        run: &str,
    ) -> anyhow::Result<String> {
        match source {
            Some(source) => {
                rewrite::dependency_attribution_identity_for_source(target, source, run)
            }
            None => rewrite::dependency_attribution_snapshot(target, run),
        }
    }
    fn lock_source_upgrade(
        &self,
        target: &std::path::Path,
    ) -> anyhow::Result<traffic_engine::coordination::SourceUpgradeGuard> {
        Ok(Box::new(rewrite::lock_admin_source_upgrade(target)?))
    }
}

#[cfg(test)]
use traffic_engine::recorded_request;
