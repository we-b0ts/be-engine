use super::super::*;

#[derive(Debug, Serialize)]
pub(crate) struct ReplayReport<S: traffic_replay::report::SessionSnapshot> {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) dependency_protocols: BTreeMap<String, native::ProtocolReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) dependency_sequence_missing: Vec<sequence::MissingDependency>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) timer_events: Vec<timers::TimerEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::replay) session_events: Option<session::Report>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(in crate::replay) session_dependency_exclusions: Vec<native::DriverPreludeExclusion>,
    pub(crate) batch_reconciliation: Option<reconciliation::BatchReconciliation>,
    pub(crate) startup_phase: startup::StartupPhaseReport,
    pub(crate) dependency_attribution_snapshot: Option<String>,
    pub(crate) dependency_hypothesis_attempts: Vec<policy::HypothesisAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dependency_hypothesis_coverage_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dependency_hypothesis_journal:
        Option<crate::policy_evidence::hypotheses::JournalManifest>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) dependency_pre_matches: Vec<crate::value_contract::pre_match::Candidate>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) case_execution_failures: Vec<Value>,
    pub(crate) connect_failures: connect_failure::Report,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) policy_witnesses: Option<crate::policy_evidence::WitnessManifest>,
    pub(crate) target_observation_coverage_error: Option<target_observation::CoverageError>,
    pub(crate) target_observation_key_context: PathBuf,
    pub(crate) target_observation_policy_fingerprint: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) egress_rejections: Vec<ReplayEgressRejections>,
    pub(crate) version: u8,
    pub(crate) session_id: String,
    pub(crate) started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finalized_at: Option<DateTime<Utc>>,
    pub(crate) finalized: bool,
    pub(crate) mode: ReplayMode,
    pub(crate) dns_listen: String,
    pub(crate) tcp_listen: String,
    pub(crate) case_dir: String,
    pub(crate) case_dependencies_path: String,
    pub(crate) active_case_id: Option<String>,
    pub(crate) cases: Vec<ReplayCaseReport>,
    pub(crate) selected_case_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_dependencies_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recording_network_path: Option<String>,
    pub(crate) targets: Vec<ReplayTarget>,
    pub(crate) unrecorded_targets: Vec<UnrecordedTargetReport>,
    pub(crate) success_detail_limit: usize,
    pub(crate) success_detail_scope: &'static str,
    pub(crate) ca_cert_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replay_policy: Option<policy::PolicyReport>,
    #[serde(flatten)]
    pub(crate) native: S,
}

impl<S: traffic_replay::report::SessionSnapshot> ReplayReport<S> {
    pub(crate) fn is_complete(&self) -> bool {
        if let Some(session) = &self.session_events {
            return session.complete();
        }
        self.active_case_id.is_none()
            && !self.cases.is_empty()
            && self
                .cases
                .iter()
                .all(|case| case.status == ReplayCaseStatus::Ended)
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.session_events
            .as_ref()
            .is_some_and(session::Report::failed)
            || self.startup_phase.is_dirty()
            || self.target_observation_coverage_error.is_some()
            || self.dependency_hypothesis_coverage_error.is_some()
            || !self.dependency_pre_matches.is_empty()
            || !self.case_execution_failures.is_empty()
            || self.connect_failures.is_dirty()
            || !self.unrecorded_targets.is_empty()
            || self.native.is_dirty()
            || self
                .dependency_protocols
                .values()
                .any(|protocol| protocol.unmatched_count > 0 || !protocol.unused_case.is_empty())
            || self
                .replay_policy
                .as_ref()
                .is_some_and(|policy| !policy.unused_applicable_dependency_rule_ids.is_empty())
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UnrecordedTargetReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) case_id: Option<String>,
    pub(crate) target: TargetKey,
    pub(crate) reason: String,
}

#[allow(dead_code)]
pub(crate) fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}
