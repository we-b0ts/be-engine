//! Format-driven comparison of authenticated text across decoded carriers.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};
use traffic_contract::compare::{AnchorClocks, LeafObservations, RuleMetadata};
use traffic_jwt::{
    contract,
    verification::{PreparedKey, Token},
};

mod paths;
mod url;

pub const RULE_ID: &str = "builtin.auth";

pub struct Metadata<'a> {
    base: &'a dyn RuleMetadata,
    matcher: Option<Matcher>,
}

impl<'a> Metadata<'a> {
    pub fn new(base: &'a dyn RuleMetadata, matcher: Option<Matcher>) -> Self {
        Self { base, matcher }
    }

    pub fn rules(&self) -> &dyn RuleMetadata {
        if self.matcher.is_some() {
            self
        } else {
            self.base
        }
    }
}

impl RuleMetadata for Metadata<'_> {
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        self.base.policies()
    }
    fn permits_scalar_composition(&self, rule: &str) -> bool {
        self.base.permits_scalar_composition(rule)
    }
    fn accepts_exact_time(&self, rule: &str) -> bool {
        self.base.accepts_exact_time(rule)
    }

    fn compare_unselected_text(
        &self,
        source: &str,
        target: &str,
        clocks: AnchorClocks,
    ) -> Option<(&'static str, LeafObservations)> {
        self.matcher
            .as_ref()?
            .compare(source, target, Carrier::Value, clocks)
            .map(|observed| (RULE_ID, observed))
    }
}

#[derive(Clone, Copy)]
pub enum Carrier {
    Value,
    Authorization,
    QueryParameter,
}

#[derive(Clone, Default)]
pub struct Matcher {
    jwt: Option<Arc<Keyring>>,
}

impl std::fmt::Debug for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Matcher")
            .field(
                "jwt_profiles",
                &self.jwt.as_ref().map_or(0, |ring| ring.keys.len()),
            )
            .finish()
    }
}

struct Keyring {
    keys: Vec<PreparedKey>,
    verified: Mutex<HashMap<[u8; 32], Option<Arc<VerifiedToken>>>>,
}

struct VerifiedToken {
    profile: usize,
    header: serde_json::Value,
    stable_claims: serde_json::Value,
    time_claims: serde_json::Value,
}

impl Matcher {
    pub fn new(keys: Vec<PreparedKey>) -> Self {
        Self {
            jwt: (!keys.is_empty()).then(|| {
                Arc::new(Keyring {
                    keys,
                    verified: Mutex::default(),
                })
            }),
        }
    }

    pub fn recognizes_authorization(&self, source: &str) -> bool {
        self.jwt
            .as_ref()
            .is_some_and(|ring| ring.verify(authorization(source).1).is_some())
    }

    pub fn compare(
        &self,
        source: &str,
        target: &str,
        carrier: Carrier,
        clocks: AnchorClocks,
    ) -> Option<LeafObservations> {
        match carrier {
            Carrier::Authorization => {
                let (a, source) = authorization(source);
                let (b, target) = authorization(target);
                (a.eq_ignore_ascii_case(b)).then_some(())?;
                self.jwt(source, target, clocks)
            }
            Carrier::QueryParameter => {
                const ENCODED_LIMIT: usize = 3 * 64 * 1024;
                if source.len() > ENCODED_LIMIT || target.len() > ENCODED_LIMIT {
                    return None;
                }
                let source = url::decoded_parameter(source)?;
                let target = url::decoded_parameter(target)?;
                self.compare(&source, &target, Carrier::Value, clocks)
            }
            Carrier::Value => {
                if self.jwt.is_some() {
                    let (scheme, token) = authorization(source);
                    if jwt_candidate(token) {
                        let (target_scheme, target) = authorization(target);
                        (scheme.eq_ignore_ascii_case(target_scheme)).then_some(())?;
                        return self.jwt(token, target, clocks);
                    }
                }
                if source.len() > 16_384 || !(source.starts_with('/') || source.starts_with("http"))
                {
                    return None;
                }
                if self.jwt.is_none() && !source.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256") {
                    return None;
                }
                url::compare(self, source, target, clocks)
            }
        }
    }

    fn jwt(&self, source: &str, target: &str, clocks: AnchorClocks) -> Option<LeafObservations> {
        let ring = self.jwt.as_ref()?;
        let a = ring.verify(source)?;
        let b = ring.verify(target)?;
        if a.profile != b.profile || a.header != b.header || a.stable_claims != b.stable_claims {
            return None;
        }
        let mut source_dates = a.time_claims.clone();
        let mut target_dates = b.time_claims.clone();
        let observation = clocks.observation();
        let anchors = observation.source.zip(observation.target).map(|(a, b)| {
            [
                traffic_contract::time::date_nanos(a),
                traffic_contract::time::date_nanos(b),
            ]
        });
        let dates = contract::compare_numeric_dates(
            &mut source_dates,
            &mut target_dates,
            anchors,
            traffic_contract::time::DEFAULT_TOLERANCE.as_nanos() as i128,
            contract::NumericDateMode::Format,
        )
        .ok()?;
        Some(LeafObservations {
            time_validations: dates.time_validations,
            identities: vec![traffic_contract::identity::IdentityPair {
                source: serde_json::to_string(source).expect("string serialization"),
                target: serde_json::to_string(target).expect("string serialization"),
            }],
            ..Default::default()
        })
    }
}

impl Keyring {
    fn verify(&self, raw: &str) -> Option<Arc<VerifiedToken>> {
        jwt_candidate(raw).then_some(())?;
        let cache_key = (raw.len() <= 8192).then(|| Sha256::digest(raw.as_bytes()).into());
        if let Some(key) = cache_key
            && let Some(cached) = self.verified.lock().ok()?.get(&key)
        {
            return cached.clone();
        }
        let result = self.verify_uncached(raw);
        if let Some(key) = cache_key
            && let Ok(mut verified) = self.verified.lock()
        {
            if verified.len() >= 256 {
                verified.clear();
            }
            verified.insert(key, result.clone());
        }
        result
    }

    fn verify_uncached(&self, raw: &str) -> Option<Arc<VerifiedToken>> {
        let mut token = Token::parse(raw)?;
        let mut matching = self
            .keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.verify(&token));
        let (profile, _) = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        let claims = token.claims.as_object_mut()?;
        let time_claims = ["iat", "nbf", "exp"]
            .into_iter()
            .filter_map(|name| claims.remove(name).map(|value| (name.to_owned(), value)))
            .collect();
        Some(Arc::new(VerifiedToken {
            profile,
            header: token.header,
            stable_claims: token.claims,
            time_claims: serde_json::Value::Object(time_claims),
        }))
    }
}

fn jwt_candidate(raw: &str) -> bool {
    if !(12..=64 * 1024).contains(&raw.len()) {
        return false;
    }
    let mut segments = raw.splitn(4, '.');
    matches!((segments.next(), segments.next(), segments.next(), segments.next()),
        (Some(a), Some(b), Some(c), None)
        if [a, b, c].into_iter().all(|part| !part.is_empty() && part.bytes().all(|byte|
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))))
}

fn authorization(raw: &str) -> (&str, &str) {
    if raw
        .as_bytes()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"Bearer "))
    {
        (&raw[..6], &raw[7..])
    } else {
        ("", raw)
    }
}

#[cfg(test)]
mod tests;
