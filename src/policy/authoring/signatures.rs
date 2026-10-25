//! Named signing profiles lower API positions to the existing crypto owners.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use crate::policy::native::{
    InputJwtEffect, InputSignedTimestampEffect, InputTimestampAlgorithm, InputTokenLocation,
    InputTokenTime, Proven, ResponseJwtEffect, ResponseJwtLocation, ResponseSigningKey, StartupKey,
};
use crate::policy::{
    NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, SignatureDefinition,
};

pub(super) mod declarations;
mod reverse;
use declarations::*;

const PREFIX: &str = "api.signature.";

#[derive(Debug, Clone)]
pub(super) struct ApiDefinitions(BTreeMap<String, Api>);
impl<'de> Deserialize<'de> for ApiDefinitions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::policy::strict_map::unique_map(deserializer).map(Self)
    }
}

enum Position<'a> {
    Header(&'a str, &'a Header),
    Query(&'a str, &'a Reference),
    Body(&'a Body),
    Json(&'a str, &'a JwtResponse),
    ResponseHeader(&'a str, &'a JwtResponse),
}

fn header_name(name: &str) -> Result<String> {
    Ok(hyper::header::HeaderName::from_bytes(name.as_bytes())?
        .as_str()
        .to_owned())
}
fn profile<'a>(
    definitions: &'a BTreeMap<String, SignatureDefinition>,
    name: &str,
) -> Result<&'a SignatureDefinition> {
    let name = if name.is_empty() { "default" } else { name };
    definitions
        .get(name)
        .with_context(|| format!("unknown signature profile {name:?}"))
}
fn jwt<'a>(
    definitions: &'a BTreeMap<String, SignatureDefinition>,
    name: &str,
) -> Result<(crate::policy::native::SignatureAlgorithm, &'a StartupKey)> {
    let SignatureDefinition::Jwt { algorithm, key } = profile(definitions, name)? else {
        anyhow::bail!("JWT position requires a JWT signature profile");
    };
    Ok((*algorithm, key))
}

fn response(
    pointer: Option<&str>,
    header: Option<&str>,
    value: &JwtResponse,
    definitions: &BTreeMap<String, SignatureDefinition>,
) -> Result<NativeEffect> {
    let (algorithm, key) = jwt(definitions, &value.signature)?;
    Ok(NativeEffect::ResponseJwt(ResponseJwtEffect {
        pointer: pointer.unwrap_or_default().into(),
        location: header
            .map(|header| {
                Ok::<_, anyhow::Error>(ResponseJwtLocation {
                    header: header_name(header)?,
                })
            })
            .transpose()?,
        algorithm,
        signing_key: ResponseSigningKey::Startup {
            source: key.clone(),
        },
        nonces: value
            .nonces
            .iter()
            .map(|nonce| Proven {
                contract: nonce.contract(),
                proof: nonce.proof.clone().or_else(|| value.proof.clone()),
            })
            .collect(),
        url_query_param: value.query.clone(),
        expires_at: value.expires_at.clone(),
        expires_at_format: value.expires_at_format,
        issued_at: value.issued_at.clone(),
        ttl: value.ttl.clone(),
    }))
}

fn without_proofs(mut rule: NativeRule) -> NativeRule {
    rule.proof = None;
    if let NativeEffect::ResponseJwt(effect) = &mut rule.effect {
        for nonce in &mut effect.nonces {
            nonce.proof = None;
        }
    }
    rule
}

fn lower(
    api: &str,
    position: Position<'_>,
    definitions: &BTreeMap<String, SignatureDefinition>,
) -> Result<NativeRule> {
    let (effect, proof) = match position {
        Position::Header(name, value) => {
            let (algorithm, key) = jwt(definitions, &value.signature)?;
            let name = header_name(name)?;
            let location = match value.scheme {
                HeaderScheme::Bearer => InputTokenLocation::BearerHeader { name },
                HeaderScheme::Raw => InputTokenLocation::RawHeader { name },
            };
            (
                NativeEffect::InputJwt(InputJwtEffect {
                    location,
                    algorithm,
                    signing_key: key.clone(),
                    time: InputTokenTime::PreserveRelative,
                }),
                value.proof.clone(),
            )
        }
        Position::Query(name, value) => {
            let (name_profile, proof) = value.parts();
            let (algorithm, key) = jwt(definitions, name_profile)?;
            (
                NativeEffect::InputJwt(InputJwtEffect {
                    location: InputTokenLocation::Query { name: name.into() },
                    algorithm,
                    signing_key: key.clone(),
                    time: InputTokenTime::PreserveRelative,
                }),
                proof.cloned(),
            )
        }
        Position::Body(value) => {
            let SignatureDefinition::Md5SortedFields { key } =
                profile(definitions, &value.signature)?
            else {
                anyhow::bail!("signed JSON body requires an md5_sorted_fields profile");
            };
            (
                NativeEffect::InputSignedTimestamp(InputSignedTimestampEffect {
                    algorithm: InputTimestampAlgorithm::Md5SortedFields,
                    fields: value.fields.clone(),
                    timestamp_pointer: value.timestamp_pointer.clone(),
                    signature_pointer: value.signature_pointer.clone(),
                    secret_parameter: value.secret_parameter.clone(),
                    signing_key: key.clone(),
                    time: InputTokenTime::PreserveRelative,
                }),
                value.proof.clone(),
            )
        }
        Position::Json(pointer, value) => {
            ensure!(
                api != "*",
                "response signatures require a concrete API selector"
            );
            (
                response(Some(pointer), None, value, definitions)?,
                value.proof.clone(),
            )
        }
        Position::ResponseHeader(header, value) => {
            ensure!(
                api != "*",
                "response signatures require a concrete API selector"
            );
            (
                response(None, Some(header), value, definitions)?,
                value.proof.clone(),
            )
        }
    };
    let mut rule = NativeRule {
        id: String::new(),
        selector: NativeMatch {
            api: (api != "*").then(|| api.into()),
            ..Default::default()
        },
        effect,
        when: None,
        proof,
    };
    let semantic = without_proofs(rule.clone());
    let hash = Sha256::digest(serde_json::to_vec(&(semantic.selector, semantic.effect))?);
    rule.id = format!("{PREFIX}{hash:x}");
    crate::policy::compile_native(&rule)?;
    Ok(rule)
}

pub(super) fn expand(
    api: Option<ApiDefinitions>,
    definitions: &BTreeMap<String, SignatureDefinition>,
) -> Result<Vec<Value>> {
    let Some(ApiDefinitions(entries)) = api else {
        return Ok(vec![]);
    };
    ensure!(
        entries.len() <= 1024,
        "API signature declarations exceed 1024 APIs"
    );
    let mut seen = BTreeSet::new();
    let mut positions = BTreeSet::new();
    let mut output = vec![];
    let mut push = |api: &str, position| -> Result<()> {
        ensure!(output.len() < 4096, "API signatures exceed 4096 positions");
        let (surface, name) = match &position {
            Position::Header(name, _) => ("request.header", header_name(name)?),
            Position::Query(name, _) => ("request.query", (*name).into()),
            Position::Body(_) => ("request.body", String::new()),
            Position::Json(pointer, _) => ("response.json", (*pointer).into()),
            Position::ResponseHeader(name, _) => ("response.header", header_name(name)?),
        };
        ensure!(
            positions.insert((api.to_owned(), surface, name)),
            "duplicate API signature position"
        );
        let rule = lower(api, position, definitions)?;
        ensure!(
            seen.insert(rule.id.clone()),
            "duplicate API signature position"
        );
        output.push(serde_yaml::to_value(rule)?);
        Ok(())
    };
    for (api, entry) in &entries {
        ensure!(
            entry
                .request
                .as_ref()
                .is_some_and(|request| !request.headers.is_empty()
                    || !request.query.is_empty()
                    || request.body.is_some())
                || entry.response.as_ref().is_some_and(
                    |response| !response.json.is_empty() || !response.headers.is_empty()
                ),
            "API signature declaration has no positions"
        );
        if let Some(request) = &entry.request {
            ensure!(
                request.headers.len() <= 128 && request.query.len() <= 128,
                "API request signature positions exceed bounds"
            );
            for (name, value) in &request.headers {
                push(api, Position::Header(name, value))?;
            }
            for (name, value) in &request.query {
                push(api, Position::Query(name, value))?;
            }
            if let Some(body) = &request.body {
                push(api, Position::Body(body))?;
            }
        }
        if let Some(response) = &entry.response {
            ensure!(
                response.json.len() <= 128 && response.headers.len() <= 128,
                "API response signature positions exceed bounds"
            );
            for (pointer, value) in &response.json {
                push(api, Position::Json(pointer, value))?;
            }
            for (header, value) in &response.headers {
                push(api, Position::ResponseHeader(header, value))?;
            }
        }
    }
    Ok(output)
}

pub(super) fn generated(rule: &PolicyRule) -> bool {
    rule.id().starts_with(PREFIX)
}

pub(super) fn compact(
    rule: &PolicyRule,
    definitions: &BTreeMap<String, SignatureDefinition>,
    root: &mut Mapping,
) -> Result<bool> {
    reverse::compact(rule, definitions, root)
}

#[cfg(test)]
mod tests;
