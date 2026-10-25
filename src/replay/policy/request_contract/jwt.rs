//! Request adapters share authenticated claims and staged nonce bindings.
use super::*;

pub(super) struct JwtContext<'a> {
    pub case: &'a str,
    pub rule: &'a str,
    pub pointer: &'a str,
    pub algorithm: crate::request_rules::JwtAlgorithm,
    pub anchors: [i128; 2],
    pub tolerance: i128,
    pub dynamic_claims: &'a [crate::request_rules::JwtDynamicClaim],
}

impl RequestContracts {
    pub(super) fn compare_jwt(
        &self,
        source: &Value,
        actual: &Value,
        context: JwtContext<'_>,
        decision: &mut Decision,
    ) -> Result<()> {
        let key = self
            .keys
            .get(&(context.rule.into(), context.pointer.into()))
            .context("request JWT signing key is unavailable")?
            .bytes();
        let validated = crate::request_rules::jwt::contract::compare(
            source,
            actual,
            crate::request_rules::jwt::contract::Contract {
                algorithm: context.algorithm,
                key,
                anchors: context.anchors,
                tolerance: context.tolerance,
                dynamic_claims: context.dynamic_claims,
            },
        )
        .map_err(|error| anyhow::anyhow!("JWT contract failed: {error:?}"))?;
        decision.time_validations += validated.time_validations;
        for nonce in validated.nonces {
            self.observe_native_identity(context.case, &nonce.source, &nonce.target, decision)?;
        }
        Ok(())
    }
}
