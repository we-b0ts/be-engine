//! Pure declaration compilation with explicitly supplied policy and codec registries.
pub mod capability;
pub mod compiler;
pub mod native_compile;
pub mod plan;
pub mod protocol_contract;
pub mod resource;
pub mod validation;
pub use capability::*;
pub use compiler::{CompiledRule, RuleEffect};
pub use native_compile::*;
pub use traffic_contract::rule::ClockScope;
use traffic_policy::PolicyRegistry;
pub use traffic_policy_schema::IdentityFormat;
pub use traffic_policy_schema::native::*;
pub use traffic_policy_schema::*;
use traffic_value::codec::CodecRegistry;

#[derive(Clone, Copy)]
pub struct CompilationContext<'a> {
    pub policies: &'a PolicyRegistry,
    pub codecs: &'a CodecRegistry,
}
impl CompilationContext<'_> {
    pub fn semantics(&self) -> serde_json::Value {
        serde_json::json!({
            "codecs": self.codecs.descriptors().map(|d| (d.id, d.version)).collect::<Vec<_>>(),
            "policies": self.policies.descriptors().map(|d| (d.id, d.version, d.actions)).collect::<Vec<_>>(),
        })
    }
}

pub use traffic_contract::codec::CodecKind;
