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

pub(in crate::replay) struct JwtComparison<'a> {
    keys: BTreeMap<String, Option<ResolvedSigningKey>>,
    nonces: BTreeMap<(String, String), NonceBindings>,
    documents: [&'a Value; 2],
}

#[derive(Default)]
struct NonceBindings {
    forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
}

impl<'a> JwtComparison<'a> {
    pub(in crate::replay) fn load(
        fields: &[ResponseField],
        policy: &Path,
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
                        ResolvedSigningKey::resolve(root, &rule.signing_key_source).ok(),
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

    pub(in crate::replay) fn compare(
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
            .and_then(Option::as_ref)
            .ok_or(ResponseDifferenceKind::JwtSigningKeyUnavailable)?;
        let token_pointer = ResponseJwtRule::concrete_pointer(&rule.pointer, pointer);
        let [Some(source), Some(target)] = self
            .documents
            .map(|document| document.pointer(&token_pointer))
        else {
            return Err(ResponseDifferenceKind::JwtInvalid);
        };
        let validated = compare(rule, source, target, times, key.bytes())?;
        if let Some(pattern) = &rule.expires_at {
            let expiry_pointer = ResponseJwtRule::concrete_pointer(pattern, pointer);
            for (document, exp) in self.documents.into_iter().zip(validated.exp) {
                let expiry = document
                    .pointer(&expiry_pointer)
                    .and_then(Value::as_str)
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
                if !expiry.is_some_and(|value| value.timestamp() == exp) {
                    return Err(ResponseDifferenceKind::JwtExpiryMismatch);
                }
            }
        }
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

pub(in crate::replay) fn compare(
    rule: &ResponseJwtRule,
    source: &Value,
    target: &Value,
    times: RequestTimes,
    key: &[u8],
) -> Result<contract::Validated, ResponseDifferenceKind> {
    let (Some(source_time), Some(target_time)) = (times.source, times.target) else {
        return Err(ResponseDifferenceKind::TimeReferenceMissing);
    };
    let nanos = |time: chrono::DateTime<chrono::Utc>| {
        i128::from(time.timestamp()) * 1_000_000_000 + i128::from(time.timestamp_subsec_nanos())
    };
    let extracted = if let Some(parameter) = &rule.url_query_param {
        let [left, right] = [source, target].map(|value| {
            value
                .as_str()
                .ok_or(ResponseDifferenceKind::JwtInvalid)
                .and_then(|raw| {
                    crate::request_rules::jwt::url_query::select(raw, parameter)
                        .map_err(|_| ResponseDifferenceKind::JwtInvalid)
                })
        });
        let (left, right) = (left?, right?);
        if left.prefix != right.prefix || left.suffix != right.suffix {
            return Err(ResponseDifferenceKind::JwtUrlMismatch);
        }
        Some([Value::String(left.token), Value::String(right.token)])
    } else {
        None
    };
    let [source, target] = extracted
        .as_ref()
        .map(|values| [&values[0], &values[1]])
        .unwrap_or([source, target]);
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
    .map_err(|failure| match failure {
        Failure::Invalid => ResponseDifferenceKind::JwtInvalid,
        Failure::Algorithm => ResponseDifferenceKind::JwtAlgorithmMismatch,
        Failure::Signature => ResponseDifferenceKind::JwtSignatureInvalid,
        Failure::Claims => ResponseDifferenceKind::JwtClaimsMismatch,
        Failure::Time => ResponseDifferenceKind::JwtTimeMismatch,
        Failure::Nonce => ResponseDifferenceKind::JwtNonceMismatch,
    })
}
