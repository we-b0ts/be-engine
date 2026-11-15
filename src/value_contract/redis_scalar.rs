//! Compose Redis scalar representations with the installed value services.
use crate::policy::GlobalField;
use crate::value_contract::json::{AnchorClocks, Comparison, VerifiedTimeCopy};
use anyhow::Result;
pub(crate) use native::{Scalar, decode};
use traffic_protocol_redis::scalar as native;
pub(crate) fn decode_field(source: &[u8], field: &GlobalField) -> Result<Option<Scalar>> {
    native::decode_field(source, field, traffic_extensions::policies())
}
pub(crate) fn decode_automatic(
    source: &[u8],
    plan: &crate::policy::CompiledJsonPolicy,
    clocks: AnchorClocks,
) -> Result<Option<Scalar>> {
    native::decode_automatic(source, plan, clocks)
}
pub(crate) fn compare(
    source: &[u8],
    target: &[u8],
    field: &GlobalField,
    settings: &crate::policy::TimePolicy,
    clocks: AnchorClocks,
    copies: &[VerifiedTimeCopy],
) -> Result<Comparison> {
    native::compare(
        &super::json::PolicyMetadata,
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
