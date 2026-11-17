//! Compiled policies, protected witnesses and observation clocks.
use super::*;
use crate::policy::{CompiledPolicy, Surface};
use crate::policy_evidence::{
    AssociationOutcome, ClockPair as WitnessClockPair, ObservationRetention, TargetRole,
    WitnessClocks, WitnessMetadata, WitnessStore,
};
use crate::value_contract::{json, time::ClockPair};

pub(super) fn source_body(request: &Value) -> Option<Value> {
    if request["body"]
        .get("decode_error")
        .is_some_and(|value| !value.is_null())
    {
        return None;
    }
    let bytes = evidence::decode(&request["body"]).ok()?;
    crate::json_value::parse(&bytes)
}

impl RequestContracts {
    #[allow(dead_code)]
    pub(crate) fn retains_value_witnesses(&self) -> bool {
        self.witnesses.is_some()
    }
    pub fn configure_compiled(&mut self, compiled: Option<Arc<CompiledPolicy>>) -> Result<()> {
        if let Some(global) = compiled
            .as_ref()
            .and_then(|policy| policy.global_json.as_ref())
            && global.signatures.needs_prepare()
        {
            let root = match self
                .input_origin
                .as_ref()
                .context("JWT runtime input origin unavailable")?
            {
                derived_inputs::InputOrigin::Root(root) => root.clone(),
                derived_inputs::InputOrigin::Policy(policy) => {
                    crate::config::resolve_unified_policy_root(policy)?
                }
            };
            global.signatures.prepare(&root)?;
        }
        self.rule_catalogue = Arc::new(
            compiled
                .as_deref()
                .map(case_plan::RuleCatalogue::new)
                .unwrap_or_default(),
        );
        self.compiled = compiled;
        Ok(())
    }

    pub(crate) fn configure_witnesses(
        &mut self,
        store: WitnessStore,
        observe_sources: bool,
    ) -> Result<()> {
        if tokio::runtime::Handle::try_current().is_ok() {
            self.hypothesis_journal = Some(store.hypothesis_journal()?);
        }
        self.witnesses = Some(store);
        if !observe_sources {
            return Ok(());
        }
        let cases = self
            .state
            .lock()
            .expect("request contracts")
            .cases
            .iter()
            .map(|(id, anchor)| (id.clone(), anchor.dependencies_path.clone()))
            .collect::<Vec<_>>();
        for (id, path) in cases {
            if crate::dependency_index::scoped::exists(&path) {
                let bytes = crate::dependency_index::scoped::read_bytes(&path)?;
                self.register_source_records(&id, &bytes, None)?;
                for line in bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                {
                    let event: Value = serde_json::from_slice(line)?;
                    if crate::dependency::observation::is_case_event(&event) {
                        self.observe_plan_fact(&id, &event);
                    }
                }
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) fn witness_manifest(&self) -> Option<crate::policy_evidence::WitnessManifest> {
        self.witnesses
            .as_ref()
            .and_then(|store| store.manifest().ok())
    }

    #[allow(dead_code)]
    #[cfg(test)]
    pub(crate) fn seal_witnesses(&self) -> Result<()> {
        if let Some(store) = &self.witnesses {
            store.sealed_manifest()?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn record_value_witness(
        &self,
        metadata: WitnessMetadata,
        source: &[u8],
        target: Option<&[u8]>,
    ) -> Result<()> {
        let Some(store) = &self.witnesses else {
            return Ok(());
        };
        let anchor = self.anchor(&metadata.source.case_id)?;
        store.record(metadata, &anchor.dir, source, target)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn record_delivery_witness(
        &self,
        id: &str,
        metadata: WitnessMetadata,
        source: &[u8],
        target: &[u8],
    ) -> Result<()> {
        let Some(store) = &self.witnesses else {
            return Ok(());
        };
        let anchor = self.anchor(&metadata.source.case_id)?;
        store.record_observation(metadata, &anchor.dir, source, Some(target), Some(id))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn record_target_observation(
        &self,
        id: &str,
        metadata: crate::policy_evidence::TargetMetadata,
        payload: &[u8],
    ) -> Result<ObservationRetention> {
        let Some(store) = &self.witnesses else {
            return Ok(ObservationRetention::Retained);
        };
        let anchor = self.anchor(&metadata.case_id)?;
        store.record_target(id, metadata, &anchor.dir, payload)
    }

    #[allow(dead_code)]
    pub(crate) fn record_independent_request(
        &self,
        id: &str,
        case: &str,
        resource: Option<crate::policy::Resource>,
        operation: &str,
        observed: DateTime<Utc>,
        payload: &[u8],
    ) -> Result<ObservationRetention> {
        let clocks = self.contract_clocks(Some(case), None, Some(observed), None, None);
        self.record_target_observation(
            id,
            crate::policy_evidence::TargetMetadata {
                case_id: case.into(),
                run_owner: None,
                surface: Surface::DependencyRequest,
                role: TargetRole::IndependentTargetObservation,
                resource,
                operation: operation.into(),
                clocks: WitnessClocks {
                    case: WitnessClockPair {
                        source: None,
                        target: clocks.case.target,
                    },
                    dependency: WitnessClockPair {
                        source: None,
                        target: clocks.dependency.target,
                    },
                    delivery: WitnessClockPair::default(),
                },
            },
            payload,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn associate_value_witness(
        &self,
        metadata: &WitnessMetadata,
        target_id: &str,
        source: Option<&[u8]>,
    ) -> Result<AssociationOutcome> {
        let Some(store) = &self.witnesses else {
            return Ok(AssociationOutcome::Retained);
        };
        let anchor = self.anchor(&metadata.source.case_id)?;
        store.associate(metadata, target_id, &anchor.dir, source)
    }

    pub(crate) fn compiled_rules(&self) -> Option<&Arc<CompiledPolicy>> {
        self.compiled.as_ref()
    }

    pub(crate) fn contract_clocks(
        &self,
        case: Option<&str>,
        source_dependency: Option<DateTime<Utc>>,
        target_dependency: Option<DateTime<Utc>>,
        source_delivery: Option<DateTime<Utc>>,
        target_delivery: Option<DateTime<Utc>>,
    ) -> json::AnchorClocks {
        let case = case.and_then(|id| {
            self.state
                .lock()
                .expect("request contracts")
                .cases
                .get(id)
                .map(|anchor| (anchor.recorded, anchor.actual))
        });
        json::AnchorClocks::for_request(
            ClockPair {
                source: case.and_then(|(recorded, _)| recorded),
                target: case.and_then(|(_, actual)| actual),
            },
            ClockPair {
                source: source_dependency,
                target: target_dependency,
            },
            ClockPair {
                source: source_delivery,
                target: target_delivery,
            },
        )
    }
}
