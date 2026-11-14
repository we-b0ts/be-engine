//! One prepared Source scope and its stable native positions for begin/end.
use std::sync::Arc;

#[cfg(test)]
use super::ReplaySource;
use crate::value_contract::plan::{EvidenceRequirements, IndexRequirements, RuleExecutionPlan};

/// Eligibility is frozen from Source selectors. Exact key/SQL/value guards still
/// run against the genuine request; this is never a claim that a rule matched.
#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct PreparedCaseRules {
    pub plans: Arc<[Arc<RuleExecutionPlan>]>,
    pub requirements: IndexRequirements,
    pub evidence: EvidenceRequirements,
    pub formats: Vec<PreparedFormat>,
    pub pre_match_protocols: Vec<crate::protocol_contract::ProtocolKind>,
    pub unsupported_pre_match_protocols: Vec<crate::protocol_contract::ProtocolKind>,
    pub native_lookup_modes:
        std::collections::BTreeMap<crate::protocol_contract::ProtocolKind, &'static str>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(in crate::replay) struct PreparedFormat {
    pub format: &'static str,
    pub declared_fields: usize,
    pub eligible_protocols: Vec<crate::protocol_contract::ProtocolKind>,
    pub semantic_kinds: std::collections::BTreeSet<&'static str>,
}

impl PreparedCaseRules {
    pub(super) fn add(&mut self, plan: &RuleExecutionPlan) {
        self.requirements
            .required
            .extend(plan.indexes.required.iter().copied());
        self.evidence.source_record |= plan.evidence.source_record;
        self.evidence.independent_target |= plan.evidence.independent_target;
        self.evidence.protected_values |= plan.evidence.protected_values;
        self.evidence.all_hypothesis_attempts |= plan.evidence.all_hypothesis_attempts;
        self.evidence.native_delivery |= plan.evidence.native_delivery;
    }

    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "inventory_scope":"effective_case_source_only_run_inventory_prepared_by_session_owners",
            "selection":"source_selector_eligible_native_guards_retained",
            "eligible_rules":self.plans.len(),
            "index_requirements":self.requirements,
            "evidence_requirements":self.evidence,
            "format_candidates":self.formats,
            "pre_match_candidate_protocols":self.pre_match_protocols,
            "unsupported_pre_match_protocols":self.unsupported_pre_match_protocols,
            "unsupported_pre_match_reason":(!self.unsupported_pre_match_protocols.is_empty()).then_some("native dependency replay exists; automatic request pre-match is not installed for these protocols"),
            "native_lookup_modes":self.native_lookup_modes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::replay) struct SourceScopeIdentity {
    pub sha256: String,
    pub source_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub(in crate::replay) struct NativeCaseRefs {
    pub http: Arc<[usize]>,
    pub redis: Arc<[usize]>,
    pub mysql: Arc<[usize]>,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct CaseExecutionPlan {
    pub case_id: String,
    pub source: SourceScopeIdentity,
    pub native: NativeCaseRefs,
    pub rules: PreparedCaseRules,
    pub sequence: Option<Arc<traffic_replay::SequencePlan>>,
}

impl CaseExecutionPlan {
    pub(in crate::replay) fn new(
        case_id: String,
        source: SourceScopeIdentity,
        native: NativeCaseRefs,
    ) -> Self {
        Self {
            case_id,
            source,
            native,
            rules: PreparedCaseRules::default(),
            sequence: None,
        }
    }
}

pub(in crate::replay) use traffic_replay::index::CaseMembership;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prepared_case_retains_native_refs_while_other_cases_are_registered() {
        let mut members = CaseMembership::default();
        members.register(ReplaySource::Case, Some("active"), 0);
        members.register(ReplaySource::Startup, Some("active"), 1);
        members.register(ReplaySource::Case, Some("active"), 2);
        members.seal();
        let plan = CaseExecutionPlan::new(
            "active".into(),
            SourceScopeIdentity {
                sha256: "scope-hash".into(),
                source_bytes: 123,
            },
            NativeCaseRefs {
                http: members.for_case("active"),
                ..Default::default()
            },
        );
        members.register(ReplaySource::Case, Some("next"), 3);
        members.seal();
        assert_eq!(plan.case_id, "active");
        assert_eq!(plan.source.source_bytes, 123);
        assert_eq!(plan.source.sha256, "scope-hash");
        assert_eq!(plan.native.http.as_ref(), [0, 2]);
        assert!(plan.native.redis.is_empty() && plan.native.mysql.is_empty());
        assert!(Arc::ptr_eq(&plan.native.http, &members.for_case("active")));
        assert_eq!(members.for_case("next").as_ref(), [3]);
    }
}
