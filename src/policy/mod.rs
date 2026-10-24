//! Self-contained traffic contracts and their protocol-independent compiled policy.
//! Compilation is pure: evidence authorization and policy persistence belong to
//! their callers, and protocol adapters retain lane/session/consumption ownership.
mod authoring;
mod capability;
pub(crate) use authoring::expanded as expand_policy;
pub(crate) use authoring::require_source_proof;
pub(crate) use authoring::retired_authoring;
pub use authoring::{effective_rules, render_policy, require_source_proofs};
mod async_api;
mod compiler;
mod declarations;
mod global_json;
mod http_global;
pub use async_api::*;
pub use http_global::*;
mod global_protocol;
mod mysql_global;
mod redis_global;
pub use declarations::*;
pub use global_json::*;
pub use global_protocol::*;
pub use mysql_global::*;
pub use redis_global::*;
mod condition;
pub mod native;
mod native_compile;
mod proof;
pub use proof::{MAX_PROOF_FACT_BYTES, MAX_PROOF_SOURCE_REFERENCES};
mod schema;
pub(crate) mod signatures;
pub use signatures::SignatureDefinition;
mod strict_map;
mod time_scope;
pub use time_scope::ClockScope;

pub use capability::*;
pub use compiler::*;
pub use native::{NativeEffect, NativeMatch, NativeRule, PolicyRule};
pub(crate) use native_compile::semantic_rule as native_semantics;
pub use native_compile::*;
pub use schema::*;

#[cfg(test)]
mod tests;
