//! Native Source assembly supplies inventories to the common Replay startup pipeline.
use super::*;
use crate::ReplayConfig;
use crate::policy::runtime::ReplayPolicyRuntime;

use crate::replay::TargetObservations;
use crate::replay::protocol_runtime::loading::{
    ProtocolSourceLoader, SourcePreparation, SourceResources,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use traffic_protocol::connection::NativeFuture;
use traffic_replay::ReplaySource;
use uuid::Uuid;

pub(crate) struct SourceLoader {
    protocols: ReplayProtocols,
    unsupported_http_options: bool,
}

impl SourceLoader {
    pub(super) fn new(config: &ReplayConfig) -> Self {
        Self {
            protocols: ReplayProtocols {
                observations: (),

                changed: Default::default(),
            },
            unsupported_http_options: !config.http_ignore_query_params.is_empty()
                || config.allowed_unused_http.is_some(),
        }
    }
}

impl ProtocolSourceLoader for SourceLoader {
    type Protocols = ReplayProtocols;
    type CaseSelector = ();

    fn install_run_scopes(&mut self, _scopes: BTreeMap<Uuid, Arc<str>>) {}

    fn load_run<'a>(
        &'a mut self,
        path: &'a Path,
        scope: ReplaySource,
        rules: &'a [crate::BackgroundDependencyRuleConfig],
        resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            source::global::load(
                path,
                scope,
                &mut resources.targets,
                rules,
                resources.reader.clone(),
                &mut resources.native,
            )
            .await
        })
    }

    fn freeze_global_layout(&mut self) {}

    fn prepare_run<'a>(
        &'a mut self,
        _root: &'a Path,
        _debug: Option<PathBuf>,
        _resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            anyhow::ensure!(
                !self.unsupported_http_options,
                "legacy HTTP matching options require an installed native permission capability"
            );
            Ok(())
        })
    }

    fn case_selector(&self) -> Self::CaseSelector {}

    fn startup_records(
        path: &Path,
        index: &crate::dependency_index::FileIndex,
        reader: &mut crate::dependency_index::RecordReader,
    ) -> Result<Vec<(usize, source::DependencyRecord)>> {
        source::startup_records(path, index, reader)
    }

    fn shared_source_lines(
        _: &Path,
        _: &crate::dependency_index::FileIndex,
        _: &mut crate::dependency_index::RecordReader,
        _: &Self::CaseSelector,
    ) -> Result<BTreeSet<usize>> {
        Ok(BTreeSet::new())
    }

    fn register_source(
        &mut self,
        batch: replay::dependencies::SourceBatch<'_, source::DependencyRecord>,
        resources: &mut SourceResources,
    ) -> Result<()> {
        source::register_dependency_records(
            batch.path,
            batch.records,
            batch.skip,
            batch.source,
            batch.case,
            &mut resources.targets,
            batch.process_rules,
            batch.cleanup,
            &mut resources.native,
        )
    }

    fn load_case_metadata<'a>(
        &'a mut self,
        _directory: &'a Path,
        _resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn prepare(
        self,
        _context: SourcePreparation,
        resources: SourceResources,
    ) -> NativeFuture<'static, (Self, SourceResources)> {
        Box::pin(async move { Ok((self, resources)) })
    }

    fn register_policy_sources(&self, _policy: &mut ReplayPolicyRuntime) -> Result<()> {
        Ok(())
    }

    fn observe_policy_sources(&self, _policy: &mut ReplayPolicyRuntime) -> Result<()> {
        Ok(())
    }

    fn finish(
        self,
        _lazy: bool,
        _observations: TargetObservations,
        _policy: Option<&ReplayPolicyRuntime>,
    ) -> Self::Protocols {
        self.protocols
    }
}
