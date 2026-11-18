//! Runtime adapters over the installed dependency catalog.
pub use traffic_engine_evidence::protocols::*;
pub mod recording;
pub mod replay;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod value_rule_tests;
