//! Compose Redis scalar representations with the installed value services.
use crate::policy::GlobalField;
use crate::value_contract::json::{AnchorClocks, Comparison, VerifiedTimeCopy};
use anyhow::Result;
pub(crate) use scalar::Scalar;
use traffic_policy_value::scalar;
pub(crate) fn decode(source: &[u8]) -> Result<Option<Scalar>> {
    scalar::decode(source, traffic_extensions::codecs())
}
pub(crate) fn decode_field(source: &[u8], field: &GlobalField) -> Result<Option<Scalar>> {
    scalar::decode_field(source, field, &super::execution_context())
}
pub(crate) fn decode_automatic(
    source: &[u8],
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<Option<Scalar>> {
    let Some(scalar) = scalar::decode_inferred(source, plan, clocks, traffic_extensions::codecs())?
    else {
        return Ok(None);
    };
    Ok(plan
        .fields_with_clocks(&scalar.logical, clocks)?
        .iter()
        .any(|(_, contract)| contract.time().is_some())
        .then_some(scalar))
}
pub(crate) fn compare(
    source: &[u8],
    target: &[u8],
    field: &GlobalField,
    settings: &crate::policy::TimePolicy,
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Result<Comparison> {
    scalar::compare(
        &super::execution_context(),
        crate::policy::GLOBAL_REDIS_ID,
        source,
        target,
        field,
        settings,
        clocks,
        &super::copy_proofs(copies),
    )
}
pub(crate) fn plan(
    field: &GlobalField,
    settings: &crate::policy::TimePolicy,
) -> crate::policy::CompiledJsonPolicy {
    crate::policy::CompiledJsonPolicy {
        time: settings.clone(),
        signatures: Default::default(),
        fields: std::collections::BTreeMap::from([(String::new(), field.clone())]),
        fingerprint: String::new(),
    }
}
