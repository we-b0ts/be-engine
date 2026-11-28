//! Session-wide finite dependencies keep their cursors across Case transitions.
use super::*;
use crate::replay::{ReplayProtocolSet, RuntimeState};
use anyhow::{Context, ensure};
use std::collections::BTreeMap;
use traffic_protocol::ProtocolId;

#[derive(Debug)]
pub(crate) struct RunBindings {
    pub(crate) runtimes: Vec<Arc<SequenceRuntime>>,
    protocols: BTreeMap<ProtocolId, Binding>,
    registered: Binding,
}

#[derive(Default)]
struct ScopeRefs {
    protocols: BTreeMap<ProtocolId, Vec<(usize, u64)>>,
    registered: Vec<(usize, u64)>,
}
fn task_scope(
    mut owner: traffic_model::attribution::DependencyOwner,
) -> traffic_model::attribution::DependencyOwner {
    if let traffic_model::attribution::DependencyOwner::Process { invocation, .. } = &mut owner {
        *invocation = None;
    }
    owner
}

impl<P: ReplayProtocolSet> RuntimeState<P> {
    pub(crate) async fn prepare_session_sequence(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let protocols = self.protocols.run_sequence_refs()?;
        let native: Vec<_> = self
            .native
            .core
            .exchanges
            .iter()
            .filter_map(|exchange| {
                let capture = exchange.source.capture.as_ref()?;
                capture
                    .semantic_required
                    .then_some((exchange.index, capture.sequence))
            })
            .collect();
        let references: std::collections::BTreeSet<_> = protocols
            .values()
            .flatten()
            .map(|reference| reference.sequence)
            .chain(native.iter().map(|(_, sequence)| *sequence))
            .collect();
        ensure!(
            references.len() == native.len() + protocols.values().map(Vec::len).sum::<usize>(),
            "session dependency sequence is bound to multiple providers"
        );
        let root = self.root_dir.clone();
        let driver_preludes = self
            .native
            .event_session_exclusions()
            .keys()
            .copied()
            .collect();
        let plan = tokio::task::spawn_blocking(move || {
            super::super::session::plan(&root, references, driver_preludes)
        })
        .await
        .context("session event preparation task failed")??;
        self.native
            .configure_session_identities(plan.dependency_count())?;
        let timer_scope = super::super::session::TIMER_SCOPE;
        self.timers.validate_session(timer_scope, &plan)?;
        self.timers.activate(Some(timer_scope));
        let mut stored = std::collections::HashMap::new();
        for &(index, sequence) in &native {
            if let Some(preparation) = self.native.stored_response_preparation(index) {
                stored.insert(sequence, (index, preparation));
            }
        }
        let responses = plan
            .events()
            .filter(|event| {
                matches!(
                    event.kind,
                    traffic_replay::EventKind::ResponseHeadersStarted
                        | traffic_replay::EventKind::ResponsePartStarted
                        | traffic_replay::EventKind::ResponseEndStarted
                        | traffic_replay::EventKind::ResponseHeaders
                        | traffic_replay::EventKind::ResponsePart
                        | traffic_replay::EventKind::ResponseEnd
                )
            })
            .filter_map(|event| stored.remove(&event.dependency_sequence))
            .collect();
        let prefetch = super::super::session::prefetch::Responses::start(responses);
        let cap = super::super::control::input_timing::source_fast_cap(self)
            .map(std::time::Duration::from_millis);
        let runtime =
            SequenceRuntime::with_session_timing(plan, cap, self.timers.event_gates(timer_scope));
        let registered = Binding::merge(vec![Binding::new(runtime.clone(), native.into_iter())]);
        let protocols = protocols
            .into_iter()
            .map(|(protocol, references)| {
                let binding = Binding::new(
                    runtime.clone(),
                    references
                        .into_iter()
                        .map(|reference| (reference.index, reference.sequence)),
                );
                (protocol, Binding::merge(vec![binding]))
            })
            .collect();
        self.run_sequence = Some(RunBindings {
            runtimes: vec![runtime.clone()],
            protocols,
            registered,
        });
        let mut session = super::super::session::Session::new(runtime, timeout);
        session.prefetch = prefetch;
        self.session_events = Some(session);
        Ok(())
    }

    pub(crate) fn prepare_run_sequence(&mut self) -> Result<()> {
        let Some(catalog) = &self.sequence_catalog else {
            return Ok(());
        };
        let mut scopes = BTreeMap::<traffic_model::attribution::DependencyOwner, ScopeRefs>::new();
        for (protocol, references) in self.protocols.run_sequence_refs()? {
            for reference in references {
                scopes
                    .entry(task_scope(reference.owner))
                    .or_default()
                    .protocols
                    .entry(protocol)
                    .or_default()
                    .push((reference.index, reference.sequence));
            }
        }
        for exchange in self.native.core.exchanges.iter() {
            if exchange.source.source.is_run_owned()
                && let Some(capture) = &exchange.source.capture
            {
                scopes
                    .entry(task_scope(capture.attribution.clone()))
                    .or_default()
                    .registered
                    .push((exchange.index, capture.sequence));
            }
        }
        let mut runtimes = Vec::new();
        let mut bindings = BTreeMap::<ProtocolId, Vec<Binding>>::new();
        let mut registered = Vec::new();
        for scope in scopes.into_values() {
            let sequence = scope
                .protocols
                .values()
                .flatten()
                .chain(&scope.registered)
                .map(|(_, sequence)| *sequence);
            let runtime = self.sequence_runtime(catalog.scope(sequence)?);
            for (protocol, references) in scope.protocols {
                bindings
                    .entry(protocol)
                    .or_default()
                    .push(Binding::new(runtime.clone(), references.into_iter()));
            }
            registered.push(Binding::new(runtime.clone(), scope.registered.into_iter()));
            runtimes.push(runtime);
        }
        self.run_sequence = Some(RunBindings {
            runtimes,
            protocols: bindings
                .into_iter()
                .map(|(protocol, bindings)| (protocol, Binding::merge(bindings)))
                .collect(),
            registered: Binding::merge(registered),
        });
        Ok(())
    }

    pub(crate) fn attach_run_sequence(&mut self) {
        if let Some(run) = &self.run_sequence {
            self.protocols.attach_run_sequence(&run.protocols);
            self.native
                .core
                .lifecycle
                .sequence
                .attach_run(run.registered.clone());
        }
    }
}
