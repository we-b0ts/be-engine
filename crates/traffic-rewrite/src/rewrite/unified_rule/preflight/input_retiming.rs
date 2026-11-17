//! Old execution after a changed delivered input requires new execution evidence.
use super::*;
use crate::policy::{CompiledJsonPolicy, Resource, TimeContract};
use crate::policy_evidence::WitnessRef;
use crate::value_contract::time::ClockPair;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnvalidatedWitness {
    case_id: String,
    surface: String,
    witness_id: Option<String>,
    target_observation_id: Option<String>,
    reason: String,
}

struct Cut {
    resource: Resource,
    source: DateTime<Utc>,
    target: DateTime<Utc>,
}

pub(super) struct Inputs {
    #[allow(dead_code)]
    times: Option<CompiledJsonPolicy>,
    cuts: Vec<Cut>,
}

impl Inputs {
    pub(super) fn new(before: &CompiledPolicy, after: &CompiledPolicy) -> Self {
        let times =
            super::super::manifest::eligibility::adds_only_json_times(before, after).then(|| {
                let mut json = after.global_json.clone().unwrap();
                let old = &before.global_json.as_ref().unwrap().fields;
                json.fields.retain(|pointer, _| !old.contains_key(pointer));
                json
            });
        Self {
            times,
            cuts: vec![],
        }
    }

    #[allow(dead_code)]
    pub(super) fn enabled(&self) -> bool {
        self.times.is_some()
    }

    #[allow(dead_code)]
    /// Called only inside the existing authenticated DeliveredInput reader,
    /// after native framing, matching request and independent clocks validate.
    pub(super) fn observe(
        &mut self,
        pointer: &str,
        source: &Value,
        delivered: &Value,
        time: &TimeContract,
        witness: &WitnessRef,
    ) -> Result<()> {
        let Some(times) = &self.times else {
            return Ok(());
        };
        // The native leaf receipt has no array/object shape. Only an exact
        // declaration can establish ownership here; do not guess wildcard
        // authority from a numeric path segment.
        if !times.fields.contains_key(pointer) {
            return Ok(());
        }
        let pair = &witness.metadata.clocks.delivery;
        let (Some(source_at), Some(target_at)) = (pair.source, pair.target) else {
            return Ok(());
        };
        let mut plan = times.clone();
        plan.fields = BTreeMap::from([(
            "/value".into(),
            crate::policy::GlobalField::Time {
                formats: vec![crate::policy::GlobalTimeFormat {
                    format: time.format,
                    utc_offset: time.utc_offset.clone(),
                }],
            },
        )]);
        let mut clocks = witness.metadata.clocks.comparison();
        clocks.observation = Some(clocks.delivery);
        let proposed = crate::value_contract::global::materialize_logical(
            &serde_json::json!({"value":source}),
            &plan,
            &[],
            clocks,
        )?;
        if proposed["value"] == *delivered {
            return Ok(());
        }
        ensure!(
            self.cuts.len() < 4096,
            "retimed input inventory exceeds its bound"
        );
        self.cuts.push(Cut {
            resource: witness
                .metadata
                .resource
                .clone()
                .context("retimed input resource missing")?,
            source: source_at,
            target: target_at,
        });
        Ok(())
    }

    pub(super) fn precedes(&self, witness: &WitnessRef) -> bool {
        let clocks = &witness.metadata.clocks.dependency;
        self.cuts.iter().any(|cut| {
            witness.metadata.resource.as_ref() == Some(&cut.resource)
                && clocks.source.is_some_and(|at| at > cut.source)
                && clocks.target.is_some_and(|at| at > cut.target)
        })
    }

    pub(super) fn precedes_response(&self, clocks: ClockPair) -> bool {
        self.cuts.iter().any(|cut| {
            clocks.source.is_some_and(|at| at > cut.source)
                && clocks.target.is_some_and(|at| at > cut.target)
        })
    }

    pub(super) fn defer(
        case: &str,
        surface: Surface,
        witness: Option<&WitnessRef>,
        result: &mut Preflight,
    ) {
        result
            .unvalidated_retimed_witnesses
            .insert(UnvalidatedWitness {
                case_id: case.into(),
                surface: format!("{surface:?}"),
                witness_id: witness.map(|w| w.id.clone()),
                target_observation_id: witness.and_then(|w| w.target_observation_id.clone()),
                reason: "preceding_delivered_input_would_change_requires_fresh_replay".into(),
            });
    }
}
