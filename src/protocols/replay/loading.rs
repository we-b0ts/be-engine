//! Native Source assembly supplies inventories to the common Replay startup pipeline.
use super::*;
use crate::ReplayConfig;
use crate::policy::runtime::ReplayPolicyRuntime;
use crate::protocols::replay::http;

use crate::protocols::replay::mysql;
use crate::replay::TargetObservations;
use crate::replay::protocol_runtime::loading::{
    ProtocolSourceLoader, SourcePreparation, SourceResources,
};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use traffic_protocol::connection::NativeFuture;
use traffic_protocol_mysql::session_identity::DependencyIdentity;
use traffic_replay::ReplaySource;
use uuid::Uuid;

pub(crate) struct SourceLoader {
    protocols: ReplayProtocols,
    identities: HashMap<Uuid, DependencyIdentity>,
    policy: Option<PathBuf>,
    shared_http: Vec<http::cross_case::HttpCrossCaseSelector>,
}

impl SourceLoader {
    pub(super) fn new(config: &ReplayConfig) -> Self {
        Self {
            protocols: ReplayProtocols {
                deferred_identities: None,
                mysql: Default::default(),
                observations: (),

                http_exchanges: Vec::new(),
                http_case_exchange_index: Default::default(),
                http_candidates: Default::default(),
                http_blackholes: Vec::new(),
                http_events: Default::default(),
                http_sequence: Default::default(),
                http_sequence_claims: BTreeMap::new(),
                http_ingress: Default::default(),
                http_ignore_query_params: config
                    .http_ignore_query_params
                    .iter()
                    .map(|value| value.to_ascii_lowercase())
                    .collect(),
                allowed_unused_http: config.allowed_unused_http.clone(),
            },
            identities: HashMap::new(),
            policy: config.policy_path.clone(),
            shared_http: Vec::new(),
        }
    }
}

impl ProtocolSourceLoader for SourceLoader {
    type Protocols = ReplayProtocols;
    type CaseSelector = Vec<http::cross_case::HttpCrossCaseSelector>;

    fn install_run_scopes(&mut self, _scopes: BTreeMap<Uuid, Arc<str>>) {}

    fn load_run<'a>(
        &'a mut self,
        path: &'a Path,
        scope: ReplaySource,
        rules: &'a [crate::BackgroundDependencyRuleConfig],
        resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            let protocols = &mut self.protocols;
            source::global::load(
                path,
                scope,
                &mut protocols.mysql,
                &mut protocols.http_exchanges,
                &mut protocols.http_blackholes,
                &mut resources.targets,
                &mut self.identities,
                rules,
                resources.reader.clone(),
                &mut resources.native,
            )
            .await
        })
    }

    fn freeze_global_layout(&mut self) {
        let protocols = &mut self.protocols;
        source::projection::freeze(
            &mut protocols.mysql,
            &mut protocols.http_events,
            protocols.http_exchanges.len(),
        );
    }

    fn prepare_run<'a>(
        &'a mut self,
        root: &'a Path,
        _debug: Option<PathBuf>,
        resources: &'a mut SourceResources,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            // Current capture scopes retain their original per-request owner.
            if self.protocols.mysql.has_global_transaction_start
                && crate::dependency_index::recording::root(root).is_none()
            {
                let transaction_root = root.to_owned();
                let transactions = tokio::task::spawn_blocking(move || {
                    mysql::transaction_ownership::prepare(&transaction_root)
                })
                .await
                .context("Global MySQL transaction ownership task failed")??;
                self.protocols
                    .mysql
                    .install_global_transactions(transactions, &mut resources.targets)?;
            }
            self.shared_http = self
                .policy
                .as_deref()
                .map(crate::policy::runtime::http_cross_case_rules)
                .transpose()?
                .unwrap_or_default()
                .into_iter()
                .map(|(_, selector)| selector)
                .collect();
            Ok(())
        })
    }

    fn case_selector(&self) -> Self::CaseSelector {
        self.shared_http.clone()
    }

    fn startup_records(
        path: &Path,
        index: &crate::dependency_index::FileIndex,
        reader: &mut crate::dependency_index::RecordReader,
    ) -> Result<Vec<(usize, source::DependencyRecord)>> {
        source::startup_records(path, index, reader)
    }

    fn shared_source_lines(
        path: &Path,
        index: &crate::dependency_index::FileIndex,
        reader: &mut crate::dependency_index::RecordReader,
        selector: &Self::CaseSelector,
    ) -> Result<BTreeSet<usize>> {
        http::cross_case::selected_source_lines(path, index, reader, selector)
    }

    fn register_source(
        &mut self,
        batch: replay::dependencies::SourceBatch<'_, source::DependencyRecord>,
        resources: &mut SourceResources,
    ) -> Result<()> {
        let protocols = &mut self.protocols;
        source::register_dependency_records(
            batch.path,
            batch.records,
            batch.skip,
            batch.source,
            batch.case,
            &mut protocols.mysql,
            &mut protocols.http_exchanges,
            &mut protocols.http_blackholes,
            &mut resources.targets,
            &mut self.identities,
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
        mut self,
        context: SourcePreparation,
        mut resources: SourceResources,
    ) -> NativeFuture<'static, (Self, SourceResources)> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<_> {
                let protocols = &mut self.protocols;
                let shared_cases = if context.lazy {
                    BTreeMap::new()
                } else {
                    context.cases.clone()
                };
                http::cross_case::load(
                    &context.root,
                    self.policy.as_deref(),
                    &shared_cases,
                    &mut protocols.http_exchanges,
                    &mut resources.targets,
                )?;
                protocols.http_case_exchange_index =
                    http::case_exchange_index(&protocols.http_exchanges);
                let selected = context.cases.keys().cloned().collect();
                protocols.mysql.set_origins(
                    mysql::ownership::load(&context.root, &context.rules)?,
                    &selected,
                );
                Ok((self, resources))
            })
            .await
            .context("native Source preparation task failed")?
        })
    }

    fn register_policy_sources(&self, _policy: &mut ReplayPolicyRuntime) -> Result<()> {
        Ok(())
    }

    fn observe_policy_sources(&self, policy: &mut ReplayPolicyRuntime) -> Result<()> {
        self.protocols.mysql.observe_registered_policy_exchanges(
            policy,
            0,
            Some(ReplaySource::Case),
        );
        http::observe_recorded_policy_exchanges(policy, &self.protocols.http_exchanges);

        policy.reject_http_ignore_overlap(&self.protocols.http_ignore_query_params)
    }

    fn finish(
        mut self,
        lazy: bool,
        _observations: TargetObservations,
        _policy: Option<&ReplayPolicyRuntime>,
    ) -> Self::Protocols {
        self.protocols.deferred_identities = lazy.then_some(self.identities);
        self.protocols
    }
}
