//! Independent request evidence belongs to the actual Case or the Replay run.
use super::*;
use crate::policy_evidence::{
    ClockPair, ObservationRetention, TargetMetadata, TargetRole, WitnessClocks, WitnessStore,
};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Instant as TokioInstant;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CoverageError {
    pub code: &'static str,
    pub owner: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub(crate) struct TargetObservations {
    store: WitnessStore,
    session_id: String,
    key_context: PathBuf,
    policy_fingerprint: String,
    failure: Arc<std::sync::Mutex<Option<CoverageError>>>,
    abort_tail: Arc<AbortTail>,
}

#[derive(Debug, Default)]
struct AbortTail {
    watching: AtomicBool,
    last: std::sync::Mutex<Option<(String, TokioInstant)>>,
}

impl TargetObservations {
    pub(crate) fn new(
        store: WitnessStore,
        session: Uuid,
        key_context: PathBuf,
        policy_fingerprint: String,
    ) -> Self {
        Self {
            store,
            session_id: session.to_string(),
            key_context,
            policy_fingerprint,
            failure: Default::default(),
            abort_tail: Default::default(),
        }
    }
    pub(super) fn watch_abort_tail(&self, case: &str, at: TokioInstant) {
        *self
            .abort_tail
            .last
            .lock()
            .expect("abort activity poisoned") = Some((case.into(), at));
        self.abort_tail.watching.store(true, Ordering::Release);
    }
    pub(super) fn abort_tail_activity(&self, case: &str) -> Option<TokioInstant> {
        self.abort_tail
            .last
            .lock()
            .expect("abort activity poisoned")
            .as_ref()
            .filter(|(id, _)| id == case)
            .map(|(_, at)| *at)
    }
    pub(super) fn end_abort_tail(&self) {
        self.abort_tail.watching.store(false, Ordering::Release);
        *self
            .abort_tail
            .last
            .lock()
            .expect("abort activity poisoned") = None;
    }
    pub(crate) fn key_context(&self) -> &Path {
        &self.key_context
    }
    pub(crate) fn policy_fingerprint(&self) -> &str {
        &self.policy_fingerprint
    }
    pub(crate) fn fail(&self, reason: &str) {
        self.fail_code("persistence_failure", "engine_io", reason);
    }
    fn fail_code(&self, code: &'static str, owner: &'static str, reason: &str) {
        self.failure
            .lock()
            .expect("Target evidence coverage poisoned")
            .get_or_insert_with(|| CoverageError {
                code,
                owner,
                reason: reason.into(),
            });
    }
    pub(crate) fn coverage_error(&self) -> Option<CoverageError> {
        self.failure
            .lock()
            .expect("Target evidence coverage poisoned")
            .clone()
    }
    pub(crate) fn retained(&self, result: &Result<ObservationRetention>) -> bool {
        match result {
            Ok(ObservationRetention::Retained) => true,
            Ok(ObservationRetention::Unavailable) => {
                self.fail_code("evidence_budget_exhausted", "engine_capacity", "independent Target request observation or protected payload budget was exhausted");
                false
            }
            Err(error) => {
                let cause = format!("{error:#}");
                if cause.contains(crate::request_headers::ENCRYPTION_KEY_ENV)
                    || cause.contains("managed request-header encryption key")
                {
                    self.fail_code("encryption_key_unavailable", "engine_configuration",
                        "independent Target request evidence requires the managed encryption key or TRAFFIC_E2E_ENCRYPTION_KEY_B64");
                } else {
                    let kind = error.chain().find_map(|error| {
                        error
                            .downcast_ref::<std::io::Error>()
                            .map(std::io::Error::kind)
                    });
                    let reason = kind.map_or_else(||"independent Target request evidence could not be persisted; inspect engine evidence configuration".to_string(),
                        |kind|format!("independent Target request evidence persistence failed ({kind:?})"));
                    self.fail_code("persistence_failure", "engine_io", &reason);
                }
                false
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &self,
        id: Uuid,
        case: Option<&str>,
        resource: Option<crate::policy::Resource>,
        operation: &str,
        observed: DateTime<Utc>,
        payload: &[u8],
    ) -> Result<ObservationRetention> {
        if let Some(case) = case
            && self.abort_tail.watching.load(Ordering::Acquire)
            && let Some((owner, at)) = self
                .abort_tail
                .last
                .lock()
                .expect("abort activity poisoned")
                .as_mut()
            && owner == case
        {
            *at = TokioInstant::now();
        }
        self.store.record_target(
            &id.to_string(),
            TargetMetadata {
                case_id: case.unwrap_or_default().into(),
                run_owner: case
                    .is_none()
                    .then(|| crate::policy_evidence::RunWitnessOwner {
                        session_id: self.session_id.clone(),
                    }),
                surface: crate::policy::Surface::DependencyRequest,
                role: TargetRole::IndependentTargetObservation,
                resource,
                operation: operation.into(),
                clocks: WitnessClocks {
                    case: ClockPair::default(),
                    dependency: ClockPair {
                        source: None,
                        target: Some(observed),
                    },
                    delivery: ClockPair::default(),
                },
            },
            &self.key_context,
            payload,
        )
    }
    pub(crate) fn manifest(&self) -> Option<crate::policy_evidence::WitnessManifest> {
        match self.store.manifest() {
            Ok(manifest) => Some(manifest),
            Err(_) => {
                self.fail("Target observation manifest unavailable");
                None
            }
        }
    }
    pub(crate) fn seal(&self) -> Result<crate::policy_evidence::WitnessManifest> {
        self.store.sealed_manifest()
    }
}
