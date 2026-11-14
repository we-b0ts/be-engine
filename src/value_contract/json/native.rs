//! Generated-value configuration adapted to the shared leaf-verification interface.
use super::Comparison;
use crate::policy::native::GeneratedResponse;

/// Secret key bytes remain borrowed from the immutable startup snapshot.
#[derive(Clone, Copy)]
pub(crate) struct NativeField<'a> {
    pub(crate) rule_id: &'a str,
    pub(crate) pointer: &'a str,
    pub(crate) contract: &'a GeneratedResponse,
    pub(crate) key: Option<&'a [u8]>,
    pub(crate) global: Option<&'a crate::policy::CompiledJsonPolicy>,
}

pub(super) fn verifier<'a>(
    field: &'a NativeField<'_>,
) -> impl Fn(traffic_contract::compare::NativeContext<'_>) -> Result<Comparison, String> + 'a {
    move |context| {
        let mut comparison = crate::value_contract::generated::compare_value_global(
            context.source,
            context.target,
            field.contract,
            field.key,
            field.rule_id,
            context.clocks,
            field.global,
        )
        .map_err(|error| format!("generated contract rejected value: {error:?}"))?;
        if field.global.is_some()
            && matches!(field.contract, GeneratedResponse::EncryptedJson { fields, .. } if fields.is_empty())
        {
            let context = serde_json::to_string(&(field.rule_id, context.pointer))
                .expect("cipher occurrence context is serializable");
            comparison.scope_schema_clocks_in(&context);
        }
        Ok(comparison)
    }
}
