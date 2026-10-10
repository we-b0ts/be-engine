//! Private response signing inputs and per-response nonce consistency.
use std::{collections::BTreeMap, path::Path};

use serde_json::Value;

use super::{RequestTimes, ResponseDifferenceKind};
use crate::{
    replay::policy::{ResponseField, ResponseJwtRule},
    request_rules::{
        jwt::contract::{self, Contract, Failure},
        keys::ResolvedSigningKey,
    },
};

#[derive(Default)]
pub(in crate::replay) struct JwtComparison {
    keys: BTreeMap<String, Option<ResolvedSigningKey>>,
    nonces: BTreeMap<(String, String), NonceBindings>,
}

#[derive(Default)]
struct NonceBindings {
    forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
}

impl JwtComparison {
    pub(in crate::replay) fn load(fields: &[ResponseField], policy: &Path) -> Self {
        let root = policy
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("."));
        let keys = fields
            .iter()
            .filter_map(|field| {
                field.jwt.as_ref().map(|rule| {
                    (
                        field.id.clone(),
                        ResolvedSigningKey::resolve(root, &rule.signing_key_source).ok(),
                    )
                })
            })
            .collect();
        Self {
            keys,
            nonces: BTreeMap::new(),
        }
    }

    pub(in crate::replay) fn compare(
        &mut self,
        field: &ResponseField,
        source: &Value,
        target: &Value,
        times: RequestTimes,
    ) -> Result<(), ResponseDifferenceKind> {
        let rule = field
            .jwt
            .as_ref()
            .ok_or(ResponseDifferenceKind::JwtInvalid)?;
        let key = self
            .keys
            .get(&field.id)
            .and_then(Option::as_ref)
            .ok_or(ResponseDifferenceKind::JwtSigningKeyUnavailable)?;
        let nonces = compare(rule, source, target, times, key.bytes())?;
        // Stage every selected claim before mutating any nonce binding.
        for nonce in &nonces {
            if let Some(bindings) = self.nonces.get(&(field.id.clone(), nonce.claim.clone()))
                && (bindings
                    .forward
                    .get(&nonce.source)
                    .is_some_and(|right| right != &nonce.target)
                    || bindings
                        .reverse
                        .get(&nonce.target)
                        .is_some_and(|left| left != &nonce.source))
            {
                return Err(ResponseDifferenceKind::JwtNonceMismatch);
            }
        }
        for nonce in nonces {
            let bindings = self
                .nonces
                .entry((field.id.clone(), nonce.claim))
                .or_default();
            bindings
                .forward
                .insert(nonce.source.clone(), nonce.target.clone());
            bindings.reverse.insert(nonce.target, nonce.source);
        }
        Ok(())
    }
}

pub(in crate::replay) fn compare(
    rule: &ResponseJwtRule,
    source: &Value,
    target: &Value,
    times: RequestTimes,
    key: &[u8],
) -> Result<Vec<contract::Nonce>, ResponseDifferenceKind> {
    let (Some(source_time), Some(target_time)) = (times.source, times.target) else {
        return Err(ResponseDifferenceKind::TimeReferenceMissing);
    };
    let nanos = |time: chrono::DateTime<chrono::Utc>| {
        i128::from(time.timestamp()) * 1_000_000_000 + i128::from(time.timestamp_subsec_nanos())
    };
    contract::compare(
        source,
        target,
        Contract {
            algorithm: rule.algorithm,
            key,
            anchors: [nanos(source_time), nanos(target_time)],
            tolerance: 5_000_000_000,
            dynamic_claims: &rule.dynamic_claims,
        },
    )
    .map(|validated| validated.nonces)
    .map_err(|failure| match failure {
        Failure::Invalid => ResponseDifferenceKind::JwtInvalid,
        Failure::Algorithm => ResponseDifferenceKind::JwtAlgorithmMismatch,
        Failure::Signature => ResponseDifferenceKind::JwtSignatureInvalid,
        Failure::Claims => ResponseDifferenceKind::JwtClaimsMismatch,
        Failure::Time => ResponseDifferenceKind::JwtTimeMismatch,
        Failure::Nonce => ResponseDifferenceKind::JwtNonceMismatch,
    })
}
