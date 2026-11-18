//! Traffic-policy authoring and normalization through explicit compilation ports.
pub mod async_api;
pub mod authoring;
pub mod declarations;
pub mod native;
pub mod sections;
pub mod signatures;
pub use async_api::*;
pub use declarations::*;
pub use native::*;
pub use sections::*;
pub use signatures::SignatureDefinition;
pub use traffic_contract::rule::ClockScope;
pub use traffic_policy_compiler::compiler;
pub use traffic_policy_compiler::compiler::validate_pointer;
pub use traffic_policy_compiler::native_compile::semantic_rule as native_semantics;
pub use traffic_policy_schema::IdentityFormat;
pub use traffic_policy_schema::*;
pub use traffic_policy_schema::{proof, strict_map};
pub use traffic_policy_value::fields::{
    GlobalField, GlobalIdentityFormat, GlobalTemplateFormat, GlobalTimeFormat, GlobalUrlFormat,
    TimePolicy,
};

pub const POLICY_FORMAT: &str = "traffic-policy/v3";

pub struct AuthoringContext<'a> {
    pub compilation: traffic_policy_compiler::CompilationContext<'a>,
    pub admit_native:
        &'a dyn Fn(&traffic_policy_compiler::CompiledNativeRule) -> anyhow::Result<()>,
}
impl AuthoringContext<'_> {
    pub fn compile_native(
        &self,
        rule: &traffic_policy_schema::native::NativeRule,
    ) -> anyhow::Result<traffic_policy_compiler::CompiledNativeRule> {
        let compiled =
            traffic_policy_compiler::native_compile::compile_definition(rule, &self.compilation)?;
        (self.admit_native)(&compiled)?;
        Ok(compiled)
    }
}
