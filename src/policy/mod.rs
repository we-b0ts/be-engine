//! Self-contained traffic contracts and their protocol-independent compiled policy.
//! Compilation is pure: evidence authorization and policy persistence belong to
//! their callers, and protocol adapters retain lane/session/consumption ownership.
mod capability;
mod compiler;
mod schema;

pub use capability::*;
pub use compiler::*;
pub use schema::*;

#[cfg(test)]
mod tests;
