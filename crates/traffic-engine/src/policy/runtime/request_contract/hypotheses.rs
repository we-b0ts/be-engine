//! Attempt evidence is independent of candidate selection and real consumption.
use super::*;
use crate::value_contract::hypothesis::{Candidate as ValueCandidate, Preview};
#[cfg(test)]
mod tests;

pub(crate) use crate::replay::policy::HypothesisAttempt;
pub(crate) use crate::replay::policy::HypothesisContext;

impl RequestContracts {
    #[allow(dead_code)]
    pub(crate) fn with_hypothesis_context(&self, context: HypothesisContext) -> Self {
        let mut owner = self.clone();
        owner.hypothesis_context = Some(Arc::new(context));
        owner
    }

    pub(crate) fn hypothesis_attempts(&self) -> Vec<HypothesisAttempt> {
        self.state
            .lock()
            .expect("request contracts")
            .hypothesis_attempts
            .clone()
    }

    pub(crate) fn hypothesis_coverage_error(&self) -> Option<String> {
        self.state
            .lock()
            .expect("request contracts")
            .hypothesis_error
            .clone()
    }

    pub(crate) fn hypothesis_journal_manifest(
        &self,
    ) -> Option<crate::policy_evidence::hypotheses::JournalManifest> {
        self.hypothesis_journal
            .as_ref()
            .map(|journal| journal.manifest())
    }

    pub(crate) async fn await_hypotheses_durable(&self) -> Result<()> {
        ensure!(
            self.hypothesis_coverage_error().is_none(),
            "hypothesis evidence coverage is incomplete"
        );
        if let Some(journal) = &self.hypothesis_journal
            && let Err(error) = journal.wait_durable().await
        {
            self.state
                .lock()
                .expect("request contracts")
                .hypothesis_error = Some("hypothesis_journal_persistence_failed".into());
            return Err(error);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn retain_hypothesis_preview(
        &self,
        mut preview: Preview,
    ) -> Option<crate::value_contract::json::Comparison> {
        let mut context = self
            .hypothesis_context
            .as_deref()
            .cloned()
            .unwrap_or_default();
        context.target_observation_id = context.target_observation_id.map(|id| {
            if id.contains(":DependencyRequest:") {
                id
            } else {
                crate::policy_evidence::target_observation_id(
                    &id,
                    crate::policy::Surface::DependencyRequest,
                    crate::policy_evidence::TargetRole::IndependentTargetObservation,
                )
            }
        });
        let needs_checkpoint = !preview.attempts.is_empty()
            && context.target_observation_id.as_ref().is_some_and(|id| {
                !self
                    .state
                    .lock()
                    .expect("request contracts")
                    .hypothesis_checkpoints
                    .contains(id)
            });
        let checkpoint = needs_checkpoint
            .then(|| {
                self.witnesses
                    .as_ref()
                    .zip(context.target_observation_id.as_deref())
                    .map(|(witnesses, id)| witnesses.hypothesis_checkpoint(id))
            })
            .flatten();
        let mut state = self.state.lock().expect("request contracts");
        if !preview.complete {
            state.hypothesis_error = Some("hypothesis_projection_budget_exhausted".into());
        }
        if let (Some(checkpoint), Some(journal), Some(id)) = (
            checkpoint,
            self.hypothesis_journal.as_ref(),
            context.target_observation_id.as_ref(),
        ) && !state.hypothesis_checkpoints.contains(id)
        {
            match checkpoint.and_then(|(witness, files)| {
                journal.append_with_protected_files(
                    &serde_json::json!({"kind":"hypothesis_witness","witness":witness}),
                    files,
                )
            }) {
                Ok(()) => {
                    state.hypothesis_checkpoints.insert(id.clone());
                }
                Err(_) => {
                    state.hypothesis_error =
                        Some("hypothesis_protected_witness_checkpoint_failed".into());
                }
            }
        }
        if self.witnesses.is_some()
            && !preview.attempts.is_empty()
            && (context.source_reference.is_null() || context.target_observation_id.is_none())
        {
            state.hypothesis_error = Some("hypothesis_observation_reference_unavailable".into());
        }
        for considered in preview.attempts {
            if state.hypothesis_attempts.len() >= 4096 {
                state.hypothesis_error = Some("hypothesis_attempt_budget_exhausted".into());
                break;
            }
            let mut candidate = considered.candidate;
            candidate.attempt_id = format!("hypothesis-{}", uuid::Uuid::new_v4());
            if let Some(comparison) = &mut preview.comparison {
                for accepted in &mut comparison.pre_matches {
                    if accepted.candidate_id == candidate.candidate_id
                        && accepted.pointer == candidate.pointer
                        && accepted.expected == candidate.expected
                        && accepted.actual == candidate.actual
                    {
                        accepted.attempt_id.clone_from(&candidate.attempt_id);
                    }
                }
            }
            let attempt = HypothesisAttempt {
                candidate,
                carrier: context.carrier.clone(),
                source_reference: context.source_reference.clone(),
                target_observation_id: context.target_observation_id.clone(),
                validation: if considered.passed {
                    "passed"
                } else {
                    "failed"
                }
                .into(),
                status: if considered.passed && preview.comparison.is_some() {
                    "candidate_validated"
                } else {
                    "rejected"
                }
                .into(),
                validation_reason: considered.reason,
            };
            if let Some(journal) = &self.hypothesis_journal
                && journal
                    .append(&serde_json::json!({"kind":"hypothesis_attempt","attempt":attempt}))
                    .is_err()
            {
                state.hypothesis_error = Some("hypothesis_journal_persistence_failed".into());
            }
            state.hypothesis_attempts.push(attempt);
        }
        if state.hypothesis_error.is_some() {
            None
        } else {
            preview.comparison
        }
    }

    pub(super) fn commit_hypothesis_attempts(&self, candidates: &[ValueCandidate]) -> Result<()> {
        if candidates.is_empty() {
            return Ok(());
        }
        let mut state = self.state.lock().expect("request contracts");
        ensure!(
            state.hypothesis_error.is_none(),
            "hypothesis evidence coverage is incomplete"
        );
        for candidate in candidates {
            if let Some(journal) = &self.hypothesis_journal
                && let Err(error)=journal.append(&serde_json::json!({"kind":"hypothesis_selected","attempt_id":candidate.attempt_id}))
            {
                state.hypothesis_error=Some("hypothesis_journal_persistence_failed".into());
                return Err(error);
            }
            if let Some(attempt) = state
                .hypothesis_attempts
                .iter_mut()
                .find(|attempt| attempt.candidate.attempt_id == candidate.attempt_id)
            {
                attempt.status = "selected".into();
            }
        }
        Ok(())
    }
}
