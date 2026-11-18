pub mod input_retiming;
pub use input_retiming::*;
pub mod resource;
pub use resource::*;
pub mod response;
pub use response::*;
pub mod source;
use crate::rewrite::*;
pub use source::*;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Preflight {
    pub capture_scopes: BTreeMap<String, String>,
    pub source_validations: usize,
    pub independent_target_validations: usize,
    pub derived_delivery_validations: usize,
    pub missing_target_witnesses: usize,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub target_comparison_failures: BTreeSet<TargetComparisonFailure>,
    #[serde(default)]
    pub unvalidated_target_witnesses: BTreeSet<response::UnvalidatedTargetWitness>,
    #[serde(default)]
    pub unvalidated_retimed_witnesses: BTreeSet<input_retiming::UnvalidatedWitness>,
    #[serde(default)]
    pub unavailable_source_values: usize,
    pub rules: BTreeMap<String, usize>,
    #[serde(default)]
    pub obligations: BTreeSet<crate::config::native_policy::SourceObligation>,
    #[serde(default)]
    pub pending_effect_evidence: BTreeSet<String>,
    #[serde(default)]
    pub stateful_target_obligations: BTreeSet<String>,
    #[serde(default)]
    pub source_scope: Option<source::SourceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<resource::ResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TargetComparisonFailure {
    pub case_id: String,
    pub surface: Surface,
    pub witness_id: Option<String>,
}
