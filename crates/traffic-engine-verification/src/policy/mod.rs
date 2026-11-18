//! Runtime policy binding and native adapter admission.
pub use traffic_engine_policy::policy::*;
pub mod runtime;

pub fn compile_policy(document: &TrafficPolicy) -> anyhow::Result<CompiledPolicy> {
    let compiled = traffic_engine_policy::policy::compile_policy(document)?;
    for native in &compiled.native {
        runtime::native_projection::validate_native_adapter(native)?;
    }
    Ok(compiled)
}
pub fn compile_native(rule: &NativeRule) -> anyhow::Result<CompiledNativeRule> {
    let compiled = traffic_engine_policy::policy::compile_native(rule)?;
    runtime::native_projection::validate_native_adapter(&compiled)?;
    Ok(compiled)
}
pub fn parse_policy(yaml: &str) -> anyhow::Result<TrafficPolicy> {
    let policy = traffic_engine_policy::policy::parse_policy(yaml)?;
    compile_policy(&policy)?;
    Ok(policy)
}
pub fn parse_and_compile_policy(yaml: &str) -> anyhow::Result<CompiledPolicy> {
    compile_policy(&traffic_engine_policy::policy::parse_policy(yaml)?)
}
