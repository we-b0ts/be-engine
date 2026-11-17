//! Native report adapters bind protocol facts to shared row and visibility contracts.
pub mod aggregate;
#[cfg(test)]
mod aggregate_tests;
pub mod artifacts;
pub mod codecs;
pub mod evidence;
pub mod ownership;
pub mod snapshot;
pub mod validation;

pub const PROTOCOLS: [&str; 0] = [];
pub fn semantics(_: &str) -> Option<String> {
    None
}
