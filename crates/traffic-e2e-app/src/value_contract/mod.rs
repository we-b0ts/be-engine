//! Pure value semantics shared by policy, protocol adapters, and assertions.
pub(crate) mod delivery;
pub(crate) mod diagnosis;
pub(crate) mod encoded;
pub(crate) mod generated;
pub(crate) mod global;
pub(crate) mod global_protocol;
pub(crate) mod http_headers;
pub(crate) mod hypothesis;
pub(crate) mod identities;
pub(crate) mod json;
pub(crate) mod plan;
pub(crate) mod pre_match;
pub(crate) mod redis_scalar;
pub(crate) mod response_constraints;
pub(crate) mod response_delivery;
pub(crate) mod state;
pub(crate) mod time;
pub(crate) mod time_copies;
pub(crate) mod url_query;

/// Application composition supplies the installed catalog and metadata semantics.
pub(crate) fn execution_context() -> traffic_policy_execution::ExecutionContext<'static> {
    traffic_policy_execution::ExecutionContext {
        codecs: traffic_extensions::codecs(),
        metadata: &json::PolicyMetadata,
    }
}

pub(crate) fn copy_proofs(
    copies: &[json::VerifiedTimeCopy],
) -> Vec<&dyn traffic_contract::compare::ValueCopyProof> {
    copies
        .iter()
        .map(|proof| proof as &dyn traffic_contract::compare::ValueCopyProof)
        .collect()
}
