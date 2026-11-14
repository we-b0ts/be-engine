//! Session-wide finite dependencies keep their cursors across Case transitions.
use super::*;
use crate::replay::{ReplayProtocolSet, RuntimeState};
use std::collections::BTreeMap;
use traffic_protocol::ProtocolId;

#[derive(Debug)]
pub(in crate::replay) struct RunBindings {
    pub(in crate::replay) runtimes: Vec<Arc<SequenceRuntime>>,
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
    pub(in crate::replay) fn prepare_run_sequence(&mut self) -> Result<()> {
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
        for exchange in &self.native.core.exchanges {
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
            let runtime = SequenceRuntime::new(catalog.scope(sequence)?);
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

    pub(in crate::replay) fn attach_run_sequence(&mut self) {
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
