//! Value execution over prepared declarations, installed codecs and host-owned services.
mod comparison;
pub mod delivery;
pub mod encoded;
pub mod global;

/// The application supplies its installed codecs and comparison capabilities.
#[derive(Clone, Copy)]
pub struct ExecutionContext<'a> {
    pub codecs: &'a traffic_value::codec::CodecRegistry,
    pub metadata: &'a dyn traffic_contract::compare::RuleMetadata,
}
