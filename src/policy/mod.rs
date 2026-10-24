//! Self-contained traffic contracts and their protocol-independent compiled policy.
//! Compilation is pure: evidence authorization and policy persistence belong to
//! their callers, and protocol adapters retain lane/session/consumption ownership.
mod authoring;
mod capability;
pub(crate) use authoring::expanded as expand_policy;
pub use authoring::render_policy;
pub(crate) use authoring::retired_authoring;
mod compiler;
mod declarations;
mod lowering;
pub use declarations::*;
pub use lowering::{ExpandedPolicy, effective_rules, is_schema_clock_group, lower_policy};
mod condition;
pub mod native;
mod native_compile;
mod proof;
pub use proof::{MAX_PROOF_FACT_BYTES, MAX_PROOF_SOURCE_REFERENCES};
mod schema;
mod strict_map;
mod time_scope;
pub use time_scope::ClockScope;

pub use capability::*;
pub use compiler::*;
pub use native::{HttpJsonField, NativeEffect, NativeMatch, NativeRule, PolicyRule};
pub use native_compile::*;
pub use schema::*;

#[cfg(test)]
mod tests;
