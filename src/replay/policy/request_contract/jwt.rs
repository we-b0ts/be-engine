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
            let key = (
                context.case.into(),
                context.rule.into(),
                format!("{}{}", context.pointer, nonce.claim),
            );
            let state = self.state.lock().expect("request contracts");
            if let Some(bindings) = state.nonces.get(&key) {
                ensure!(
                    (bindings.contains_key(&nonce.source) || bindings.len() < 256)
                        && bindings.iter().all(|(left, right)| {
                            (left != &nonce.source || right == &nonce.target)
                                && (right != &nonce.target || left == &nonce.source)
                        }),
                    "JWT nonce binding is inconsistent"
                );
            }
            drop(state);
            ensure!(
                decision.nonces.iter().all(|(pending_key, left, right)| {
                    pending_key != &key
                        || ((left != &nonce.source || right == &nonce.target)
                            && (right != &nonce.target || left == &nonce.source))
                }),
                "JWT nonce binding is inconsistent"
            );
            decision.nonces.push((key, nonce.source, nonce.target));
        }
        Ok(())
    }
}
