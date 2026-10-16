//! Self-contained traffic contracts and their protocol-independent compiled policy.
//! Compilation is pure: evidence authorization and policy persistence belong to
//! their callers, and protocol adapters retain lane/session/consumption ownership.
mod capability;
mod compiler;
pub mod native;
mod native_compile;
mod schema;
mod strict_map;

pub use capability::*;
pub use compiler::*;
pub use native::{NativeEffect, NativeMatch, NativeRule, PolicyRule};
pub use native_compile::*;
pub use schema::*;

#[cfg(test)]
mod tests;
