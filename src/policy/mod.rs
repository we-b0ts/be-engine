//! Self-contained traffic contracts and their protocol-independent compiled policy.
//! Compilation is pure: evidence authorization and policy persistence belong to
//! their callers, and protocol adapters retain lane/session/consumption ownership.
mod authoring;
mod capability;
pub(crate) use authoring::expanded as expand_policy;
pub use authoring::render_policy;
pub(crate) use authoring::retired_authoring;
mod compiler;
pub mod native;
mod native_compile;
mod schema;
mod strict_map;

pub use capability::*;
pub use compiler::*;
pub use native::{HttpJsonField, NativeEffect, NativeMatch, NativeRule, PolicyRule};
pub use native_compile::*;
pub use schema::*;

#[cfg(test)]
mod tests;
