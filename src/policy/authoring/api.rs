//! API declarations bind codecs and crypto locations to existing native owners.
//! Ordinary plaintext formats remain in the carrier-independent JSON plan.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use super::signatures::declarations::{JwtResponse, Request};
use crate::policy::native::{
    CipherEnvelope, EncryptionKey, GeneratedEffect, GeneratedResponse, Proven,
};
use crate::policy::{
    NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, SignatureDefinition,
};

const PREFIX: &str = "api.binding.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DocxDefinition {
    fields: Vec<DocxTimestamp>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DocxTimestamp {
    kind: TimestampKind,
    part: String,
    element: String,
    format: crate::policy::TimestampFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TimestampKind {
    Timestamp,
}

pub(super) struct ApiDefinitions(BTreeMap<String, Api>);
impl<'de> Deserialize<'de> for ApiDefinitions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::policy::strict_map::unique_map(deserializer).map(Self)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Api {
    #[serde(default)]
    request: Option<Request>,
    #[serde(default)]
    response: Option<Response>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    #[serde(default, deserialize_with = "crate::policy::strict_map::unique_map")]
    json: BTreeMap<String, ResponseJson>,
    #[serde(default, deserialize_with = "crate::policy::strict_map::unique_map")]
    headers: BTreeMap<String, ResponseHeader>,
    #[serde(default)]
    body: Option<BodyBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyBinding {
    codec: String,
    #[serde(default)]
    proof: Option<Proof>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedJson {
    encoding: CipherBinding,
    #[serde(default)]
    proof: Option<Proof>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ResponseJson {
    Signature(JwtResponse),
    Decoded(DecodedJson),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ResponseHeader {
    Signature(JwtResponse),
    Date(HeaderDate),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherBinding {
    envelope: CipherEnvelope,
    key: EncryptionKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderDate {
    kind: DateKind,
    #[serde(default)]
    parameter: Option<String>,
    format: String,
    #[serde(default)]
    proof: Option<Proof>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum DateKind {
    Date,
}

fn lower(api: &str, effect: Value, proof: Option<&Proof>) -> Result<NativeRule> {
    ensure!(
        api != "*",
        "response codec bindings require a concrete API selector"
    );
    let mut rule = serde_yaml::to_value(NativeRule {
        id: "api.binding.pending".into(),
        selector: NativeMatch {
            api: Some(api.into()),
            ..Default::default()
        },
        effect: NativeEffect::ResponseGenerated(GeneratedEffect {
            fields: BTreeMap::new(),
        }),
        proof: proof.cloned(),
        when: None,
    })?;
    rule["effect"] = effect;
    super::walk::expand_rule(&mut rule, None)?;
    let mut rule: NativeRule = serde_yaml::from_value(rule)?;
    let mut semantic = crate::policy::native_semantics(&rule)?;
    semantic
        .as_object_mut()
        .expect("native object")
        .remove("id");
    rule.id = format!(
        "{PREFIX}{:x}",
        Sha256::digest(serde_json::to_vec(&semantic)?)
    );
    crate::policy::compile_native(&rule)?;
    Ok(rule)
}

pub(super) fn expand(
    entries: Option<ApiDefinitions>,
    definitions: &BTreeMap<String, SignatureDefinition>,
    docx: Option<&DocxDefinition>,
) -> Result<Vec<Value>> {
    let Some(ApiDefinitions(entries)) = entries else {
        ensure!(
            docx.is_none(),
            "docx.fields requires an API body codec binding"
        );
        return Ok(vec![]);
    };
    ensure!(entries.len() <= 1024, "API declarations exceed 1024 APIs");
    if let Some(docx) = docx {
        ensure!(
            (1..=128).contains(&docx.fields.len()),
            "DOCX requires 1..128 fields"
        );
        let mut fields = BTreeSet::new();
        for field in &docx.fields {
            ensure!(
                fields.insert((&field.part, &field.element)),
                "duplicate DOCX timestamp position"
            );
        }
    }
    let mut signatures = Mapping::new();
    let mut output = vec![];
    let mut docx_bound = false;
    for (api, entry) in entries {
        let before = output.len();
        let mut crypto = Mapping::new();
        if let Some(request) = entry.request {
            crypto.insert("request".into(), serde_yaml::to_value(request)?);
        }
        if let Some(response) = entry.response {
            ensure!(
                response.json.len() <= 128 && response.headers.len() <= 128,
                "API response positions exceed bounds"
            );
            let mut crypto_response = Mapping::new();
            let mut json = Mapping::new();
            for (pointer, value) in response.json {
                match value {
                    ResponseJson::Decoded(decoded) => {
                        let effect = NativeEffect::ResponseGenerated(GeneratedEffect {
                            fields: BTreeMap::from([(
                                pointer,
                                Proven {
                                    contract: GeneratedResponse::EncryptedJson {
                                        envelope: decoded.encoding.envelope,
                                        key: decoded.encoding.key,
                                        fields: BTreeMap::new(),
                                    },
                                    proof: decoded.proof.clone(),
                                },
                            )]),
                        });
                        output.push(serde_yaml::to_value(lower(
                            &api,
                            serde_yaml::to_value(effect)?,
                            decoded.proof.as_ref(),
                        )?)?);
                    }
                    ResponseJson::Signature(signature) => {
                        json.insert(pointer.into(), serde_yaml::to_value(signature)?);
                    }
                }
            }
            if !json.is_empty() {
                crypto_response.insert("json".into(), json.into());
            }
            let mut headers = Mapping::new();
            let mut header_names = BTreeSet::new();
            for (header, value) in response.headers {
                let header = hyper::header::HeaderName::from_bytes(header.as_bytes())?
                    .as_str()
                    .to_owned();
                ensure!(
                    header_names.insert(header.clone()),
                    "duplicate case-insensitive API response header"
                );
                match value {
                    ResponseHeader::Date(date) => {
                        let DateKind::Date = date.kind;
                        let mut effect = Mapping::new();
                        effect.insert("kind".into(), "response_header_date".into());
                        effect.insert("header".into(), header.into());
                        effect.insert("format".into(), date.format.into());
                        if let Some(parameter) = date.parameter {
                            effect.insert("parameter".into(), parameter.into());
                        }
                        output.push(serde_yaml::to_value(lower(
                            &api,
                            effect.into(),
                            date.proof.as_ref(),
                        )?)?);
                    }
                    ResponseHeader::Signature(signature) => {
                        headers.insert(header.into(), serde_yaml::to_value(signature)?);
                    }
                }
            }
            if !headers.is_empty() {
                crypto_response.insert("headers".into(), headers.into());
            }
            if let Some(body) = response.body {
                ensure!(
                    body.codec == "docx",
                    "API body binding supports the declared DOCX codec only"
                );
                let docx = docx.context("DOCX body binding requires root docx.fields")?;
                docx_bound = true;
                let mut effect = Mapping::new();
                effect.insert("kind".into(), "response_body".into());
                effect.insert("codec".into(), "docx".into());
                effect.insert("fields".into(), serde_yaml::to_value(&docx.fields)?);
                output.push(serde_yaml::to_value(lower(
                    &api,
                    effect.into(),
                    body.proof.as_ref(),
                )?)?);
            }
            if !crypto_response.is_empty() {
                crypto.insert("response".into(), crypto_response.into());
            }
        }
        ensure!(
            !crypto.is_empty() || output.len() > before,
            "API declaration has no positions"
        );
        if !crypto.is_empty() {
            signatures.insert(api.into(), crypto.into());
        }
    }
    ensure!(
        docx.is_none() || docx_bound,
        "docx.fields requires an API body codec binding"
    );
    let signatures = if signatures.is_empty() {
        None
    } else {
        Some(serde_yaml::from_value(signatures.into())?)
    };
    output.extend(super::signatures::expand(signatures, definitions)?);
    ensure!(
        output.len() <= 4096,
        "API declarations exceed 4096 positions"
    );
    Ok(output)
}

pub(super) fn generated(rule: &PolicyRule) -> bool {
    rule.id().starts_with(PREFIX)
}

fn mapping<'a>(parent: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping> {
    parent
        .entry(key.into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .with_context(|| format!("API {key} requires a mapping"))
}

pub(super) fn compact(rule: &PolicyRule, root: &mut Mapping) -> Result<bool> {
    let Some(native) = rule.as_native().filter(|_| generated(rule)) else {
        return Ok(false);
    };
    let Some(api) = &native.selector.api else {
        return Ok(false);
    };
    let mut clean = serde_yaml::to_value(native)?;
    super::walk::compact_rule(&mut clean, None)?;
    let canonical = lower(api, clean["effect"].clone(), None)?;
    if crate::policy::native_semantics(native)? != crate::policy::native_semantics(&canonical)? {
        return Ok(false);
    }
    let (collection, name, value) = match &native.effect {
        NativeEffect::ResponseGenerated(effect) if effect.fields.len() == 1 => {
            let (pointer, field) = effect.fields.iter().next().expect("one field");
            let GeneratedResponse::EncryptedJson {
                envelope,
                key,
                fields,
            } = &field.contract
            else {
                return Ok(false);
            };
            if !fields.is_empty() {
                return Ok(false);
            }
            let mut encoding = Mapping::new();
            encoding.insert("envelope".into(), serde_yaml::to_value(envelope)?);
            encoding.insert("key".into(), serde_yaml::to_value(key)?);
            let mut decoded = Mapping::new();
            decoded.insert("encoding".into(), encoding.into());
            (Some("json"), pointer.clone(), Value::Mapping(decoded))
        }
        NativeEffect::ResponseHeaderDate(effect) => {
            let mut value = Mapping::new();
            value.insert("kind".into(), "date".into());
            value.insert("format".into(), effect.format.clone().into());
            if let Some(parameter) = &effect.parameter {
                value.insert("parameter".into(), parameter.clone().into());
            }
            (Some("headers"), effect.header.clone(), value.into())
        }
        NativeEffect::ResponseBody(effect)
            if effect.codec == crate::policy::native::BodyCodec::Docx =>
        {
            let mut declaration = Mapping::new();
            declaration.insert("fields".into(), clean["effect"]["fields"].clone());
            let declaration = Value::Mapping(declaration);
            if let Some(existing) = root.get("docx") {
                if existing != &declaration {
                    return Ok(false);
                }
            } else {
                root.insert("docx".into(), declaration);
            }
            (None, "body".into(), serde_yaml::from_str("{codec: docx}")?)
        }
        _ => return Ok(false),
    };
    let response = mapping(mapping(mapping(root, "api")?, api)?, "response")?;
    let positions = if let Some(collection) = collection {
        mapping(response, collection)?
    } else {
        response
    };
    ensure!(
        !positions.contains_key(&name),
        "duplicate API response binding"
    );
    positions.insert(name.into(), value);
    Ok(true)
}

#[cfg(test)]
mod tests;
