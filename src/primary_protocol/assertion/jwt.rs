//! Private response signing inputs and per-response nonce consistency.
use std::{collections::BTreeMap, path::Path};

use serde_json::Value;

use super::{RequestTimes, ResponseDifferenceKind};
pub(crate) mod companions;
pub(crate) mod keys;
mod rsa;
mod url;
use crate::policy::runtime::ResponseField;
use crate::policy::runtime::ResponseJwtRule;
use crate::request_rules::jwt::contract;
use crate::request_rules::jwt::contract::Contract;
use crate::request_rules::jwt::contract::Failure;

pub(crate) struct JwtComparison<'a> {
    keys: BTreeMap<String, anyhow::Result<keys::VerificationKey>>,
    nonces: BTreeMap<(String, String), NonceBindings>,
    documents: [&'a Value; 2],
}

#[derive(Default)]
struct NonceBindings {
    forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
}

impl<'a> JwtComparison<'a> {
    pub(crate) fn load(
        fields: &[ResponseField],
        policy: &Path,
        request: &Path,
        source: &'a Value,
        target: &'a Value,
    ) -> Self {
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
                        keys::VerificationKey::resolve(
                            root,
                            &rule.signing_key_source,
                            request.parent().unwrap_or(Path::new(".")),
                        ),
                    )
                })
            })
            .collect();
        Self {
            keys,
            nonces: BTreeMap::new(),
            documents: [source, target],
        }
    }

    pub(crate) fn compare(
        &mut self,
        field: &ResponseField,
        pointer: &str,
        times: RequestTimes,
    ) -> Result<(), ResponseDifferenceKind> {
        let rule = field
            .jwt
            .as_ref()
            .ok_or(ResponseDifferenceKind::JwtInvalid)?;
        let key = self
            .keys
            .get(&field.id)
            .and_then(|key| key.as_ref().ok())
            .ok_or(ResponseDifferenceKind::JwtSigningKeyUnavailable)?;
        let token_pointer = ResponseJwtRule::concrete_pointer(&rule.pointer, pointer);
        let [Some(source), Some(target)] = self
            .documents
            .map(|document| document.pointer(&token_pointer))
        else {
            return Err(ResponseDifferenceKind::JwtInvalid);
        };
        let validated = compare(rule, source, target, times, &key.bytes, key.kid.as_deref())?;
        companions::compare(rule, pointer, self.documents, &validated)?;
        let nonces = validated.nonces;
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

pub(crate) fn compare(
    rule: &ResponseJwtRule,
    source: &Value,
    target: &Value,
    times: RequestTimes,
    key: &[u8],
    kid: Option<&str>,
) -> Result<contract::Validated, ResponseDifferenceKind> {
    let (Some(source_time), Some(target_time)) = (times.source, times.target) else {
        return Err(ResponseDifferenceKind::TimeReferenceMissing);
    };
    let nanos = |time: chrono::DateTime<chrono::Utc>| {
        i128::from(time.timestamp()) * 1_000_000_000 + i128::from(time.timestamp_subsec_nanos())
    };
    let extracted = url::extract(rule, source, target)?;
    let [source, target] = extracted
        .as_ref()
        .map(|values| [&values.tokens[0], &values.tokens[1]])
        .unwrap_or([source, target]);
    let anchors = [nanos(source_time), nanos(target_time)];
    let validated = if let Some(algorithm) = rule.algorithm.hmac() {
        contract::compare(
            source,
            target,
            Contract {
                algorithm,
                key,
                anchors,
                tolerance: crate::value_contract::time::DEFAULT_TOLERANCE.as_nanos() as i128,
                dynamic_claims: &rule.dynamic_claims,
            },
        )
    } else {
        rsa::compare(source, target, key, kid, anchors, &rule.dynamic_claims)
    };
    let validated = validated.map_err(|failure| match failure {
        Failure::Invalid => ResponseDifferenceKind::JwtInvalid,
        Failure::Algorithm => ResponseDifferenceKind::JwtAlgorithmMismatch,
        Failure::Signature => ResponseDifferenceKind::JwtSignatureInvalid,
        Failure::Claims => ResponseDifferenceKind::JwtClaimsMismatch,
        Failure::Time => ResponseDifferenceKind::JwtTimeMismatch,
        Failure::Nonce => ResponseDifferenceKind::JwtNonceMismatch,
    })?;
    if rule.ttl.is_none()
        && let [Some(source_iat), Some(target_iat)] = validated.iat
        && validated.exp[0].checked_sub(source_iat) != validated.exp[1].checked_sub(target_iat)
    {
        return Err(ResponseDifferenceKind::JwtTimeMismatch);
    }
    if let Some(extracted) = &extracted {
        for (claim, echoes) in &extracted.echoes {
            if !validated.nonces.iter().any(|nonce| {
                &nonce.claim == claim && nonce.source == echoes[0] && nonce.target == echoes[1]
            }) {
                return Err(ResponseDifferenceKind::JwtNonceMismatch);
            }
        }
    }
    Ok(validated)
}

/// A decoded signature still has a complete token identity across carriers.
/// Parsing claims alone cannot authorize splitting one Source token into two.
pub(crate) fn identity_pair(
    rule: &ResponseJwtRule,
    source: &Value,
    target: &Value,
) -> Result<crate::value_contract::identities::IdentityPair, ResponseDifferenceKind> {
    let extracted = url::extract(rule, source, target)?;
    let [source, target] = extracted
        .as_ref()
        .map(|value| [&value.tokens[0], &value.tokens[1]])
        .unwrap_or([source, target]);
    Ok(crate::value_contract::identities::IdentityPair {
        source: serde_json::to_string(source).map_err(|_| ResponseDifferenceKind::JwtInvalid)?,
        target: serde_json::to_string(target).map_err(|_| ResponseDifferenceKind::JwtInvalid)?,
    })
}
