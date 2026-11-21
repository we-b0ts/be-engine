//! Pure value semantics shared by policy, protocol adapters, and assertions.
pub mod delivery;
pub mod diagnosis;
pub mod encoded;
pub mod generated;
pub mod global;
pub mod global_protocol;
pub mod http_headers;
pub mod hypothesis;
pub mod identities;
pub mod json;
pub mod plan;
pub mod pre_match;
pub mod redis_scalar;
pub mod response_constraints;
pub mod response_delivery;
pub mod state;
pub mod time;
pub mod time_copies;
pub mod url_query;

/// Application composition supplies the installed catalog and metadata semantics.
pub fn execution_context() -> traffic_policy_execution::ExecutionContext<'static> {
    traffic_policy_execution::ExecutionContext {
        codecs: traffic_extensions::codecs(),
        metadata: &json::PolicyMetadata,
    }
}

pub fn copy_proofs(
    copies: &[json::VerifiedTimeCopy],
) -> Vec<&dyn traffic_contract::compare::ValueCopyProof> {
    copies
        .iter()
        .map(|proof| proof as &dyn traffic_contract::compare::ValueCopyProof)
        .collect()
}
