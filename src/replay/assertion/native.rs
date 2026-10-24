//! Native JSON assertions share traversal, strict remainder and staged bindings.
pub(super) mod body;
mod header_jwt;
#[cfg(test)]
mod tests;
pub(crate) use body::{compare_body, compare_header};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::policy::native::{BodyCodec, BodyField, BodySelector, GeneratedResponse, NativeEffect};
use crate::policy::{CompiledNativeRule, CompiledPolicy, CompiledRule, FieldContract};
use crate::replay::policy::native_crypto_key::EncryptionKeySnapshot;
use crate::value_contract::json::{
    self, AnchorClocks, Comparison, Field, LeafContext, LeafObservations, NativeField,
    NonceIdentity, VerifiedField,
};

struct GeneratedField {
    id: String,
    pointer: String,
    contract: GeneratedResponse,
    key: Option<EncryptionKeySnapshot>,
}

struct JwtField {
    id: String,
    rule: crate::replay::policy::ResponseJwtRule,
    key: super::jwt::keys::VerificationKey,
}

/// Keys are resolved once from frozen startup inputs or immutable Source data.
/// This deliberately has no Debug/Serialize: key bytes cannot enter reports.
pub(crate) struct NativeResponseContext {
    generated: Vec<GeneratedField>,
    jwt: Vec<JwtField>,
    header_jwt: Vec<JwtField>,
    fields: Vec<(String, String, FieldContract)>,
    joined: Vec<(String, String, String)>,
    codec: Option<crate::policy::Codec>,
    codec_ids: Vec<String>,
}

pub(crate) fn needs_startup(rules: &[&CompiledNativeRule]) -> bool {
    rules.iter().any(|rule| match &rule.rule.effect {
        NativeEffect::ResponseJwt(effect) => matches!(
            effect.signing_key,
            crate::policy::native::ResponseSigningKey::Startup { .. }
        ),
        NativeEffect::ResponseGenerated(effect) => effect
            .fields
            .values()
            .any(|value| matches!(value.contract, GeneratedResponse::EncryptedJson { .. })),
        _ => false,
    })
}

pub(crate) fn selected<'a>(
    compiled: &'a CompiledPolicy,
    method: &str,
    path: &str,
    source_body: Option<&Value>,
) -> Vec<&'a CompiledNativeRule> {
    compiled
        .native
        .iter()
        .filter(|compiled| {
            let guard = crate::replay::policy::native_projection::NativeScopeGuard::from_rule(
                &compiled.rule,
            );
            guard.matches_case(method, path, source_body)
        })
        .collect()
}

impl NativeResponseContext {
    #[cfg(test)]
    pub(crate) fn load(
        compiled: &CompiledPolicy,
        method: &str,
        path: &str,
        source_body: Option<&Value>,
        target_root: &Path,
        case_dir: &Path,
    ) -> Result<Self> {
        Self::from_rules(
            &selected(compiled, method, path, source_body),
            target_root,
            case_dir,
        )
    }

    pub(crate) fn from_rules(
        rules: &[&CompiledNativeRule],
        target_root: &Path,
        case_dir: &Path,
    ) -> Result<Self> {
        let root = target_root;
        let mut output = Self {
            generated: vec![],
            jwt: vec![],
            header_jwt: vec![],
            fields: vec![],
            joined: vec![],
            codec: None,
            codec_ids: vec![],
        };
        for compiled in rules {
            let rule = &compiled.rule;
            match &rule.effect {
                NativeEffect::ResponseGenerated(effect) => {
                    output.add_codec(crate::policy::Codec::Json)?;
                    for (pointer, value) in &effect.fields {
                        let key =
                            if let GeneratedResponse::EncryptedJson { key, .. } = &value.contract {
                                Some(EncryptionKeySnapshot::resolve(root, key)?)
                            } else {
                                None
                            };
                        output.generated.push(GeneratedField {
                            id: rule.id.clone(),
                            pointer: pointer.clone(),
                            contract: value.contract.clone(),
                            key,
                        });
                    }
                }
                NativeEffect::ResponseJwt(effect) => {
                    if effect.location.is_none() {
                        output.add_codec(crate::policy::Codec::Json)?;
                    }
                    let jwt = crate::replay::policy::native_projection::project_jwt(
                        effect,
                        rule.proof.as_ref(),
                    )?;
                    let resource = match &effect.signing_key {
                        crate::policy::native::ResponseSigningKey::RecordedPublicKey {
                            resource,
                            ..
                        } => Some(resource.as_ref()),
                        _ => None,
                    };
                    let key = super::jwt::keys::VerificationKey::resolve_scoped(
                        root,
                        &jwt.signing_key_source,
                        case_dir,
                        resource,
                    )?;
                    let fields = if effect.location.is_some() {
                        &mut output.header_jwt
                    } else {
                        &mut output.jwt
                    };
                    fields.push(JwtField {
                        id: rule.id.clone(),
                        rule: jwt,
                        key,
                    });
                }
                NativeEffect::ResponseBody(effect) if effect.codec == BodyCodec::Json => {
                    output.add_codec(crate::policy::Codec::Json)?;
                    for value in &effect.fields {
                        match &value.contract {
                            BodyField::Unordered {
                                selector: BodySelector::Json { pointer },
                            } => output.fields.push((
                                rule.id.clone(),
                                pointer.clone(),
                                FieldContract::Unordered,
                            )),
                            BodyField::JoinedString {
                                selector: BodySelector::Json { pointer },
                                separator,
                            } => output.joined.push((
                                rule.id.clone(),
                                pointer.clone(),
                                separator.clone(),
                            )),
                            _ => {
                                anyhow::bail!("native JSON body contains another codec's selector")
                            }
                        }
                    }
                }
                NativeEffect::ResponseBody(effect) if effect.codec == BodyCodec::Protobuf => {
                    output.add_codec(
                        effect
                            .value_codec()?
                            .context("native Protobuf codec is absent")?,
                    )?;
                    for value in &effect.fields {
                        let (selector, unordered, separator) = match &value.contract {
                            BodyField::Unordered { selector } => (selector, true, None),
                            BodyField::JoinedString {
                                selector,
                                separator,
                            } => (selector, false, Some(separator)),
                            _ => anyhow::bail!("Protobuf body cannot own a package timestamp"),
                        };
                        let BodySelector::Protobuf { alias, .. } = selector else {
                            anyhow::bail!("Protobuf body requires a typed wire selector")
                        };
                        if unordered {
                            output.fields.push((
                                rule.id.clone(),
                                alias.clone(),
                                FieldContract::Unordered,
                            ));
                        } else {
                            output.joined.push((
                                rule.id.clone(),
                                format!("{alias}/*"),
                                separator.unwrap().clone(),
                            ));
                        }
                    }
                }
                _ => (),
            }
        }
        Ok(output)
    }

    fn add_codec(&mut self, codec: crate::policy::Codec) -> Result<()> {
        if let Some(current) = &mut self.codec {
            crate::value_contract::encoded::merge_codec(current, &codec)?;
        } else {
            self.codec = Some(codec);
        }
        Ok(())
    }

    pub(crate) fn payload_codec(&self, rules: &[&CompiledRule]) -> Result<crate::policy::Codec> {
        let mut codec = if rules.is_empty() {
            self.codec
                .clone()
                .context("response has no value contracts")?
        } else {
            crate::value_contract::encoded::merged_codec(rules)?
        };
        if let Some(native) = &self.codec {
            crate::value_contract::encoded::merge_codec(&mut codec, native)?;
        }
        Ok(codec)
    }

    pub(crate) fn compare_encoded(
        &self,
        source: &[u8],
        target: &[u8],
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        self.compare_encoded_global(source, target, rules, None, clocks)
    }

    pub(crate) fn compare_encoded_global(
        &self,
        source: &[u8],
        target: &[u8],
        rules: &[&CompiledRule],
        global: Option<&crate::policy::CompiledJsonPolicy>,
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        let codec = self.payload_codec(rules)?;
        let (source, target) = if matches!(codec, crate::policy::Codec::Protobuf(_)) {
            super::protobuf::payload_pair(source, target)?
        } else {
            (source, target)
        };
        let source = crate::value_codec::CodecView::decode(&codec, source)?;
        let target = crate::value_codec::CodecView::decode(&codec, target)?;
        let mut paths = self
            .fields
            .iter()
            .map(|(_, pointer, _)| pointer.clone())
            .chain(self.joined.iter().map(|(_, pointer, _)| pointer.clone()))
            .chain(self.generated.iter().map(|field| field.pointer.clone()))
            .chain(self.jwt.iter().flat_map(|field| {
                std::iter::once(field.rule.pointer.clone())
                    .chain(field.rule.companion_pointers().map(str::to_owned))
                    .chain(field.rule.ttl.iter().cloned())
            }))
            .collect::<Vec<_>>();
        if let Some(global) = global {
            paths.extend(
                global
                    .fields_with_clocks(&source.logical, clocks)?
                    .into_iter()
                    .map(|(pointer, _)| pointer),
            );
        }
        let protocol_checks = global
            .map(|plan| crate::value_contract::global_protocol::checks(plan, &source.logical))
            .transpose()?;
        if let Some(checks) = &protocol_checks {
            paths.extend(
                checks
                    .fields()
                    .into_iter()
                    .map(|field| field.pointer.to_owned()),
            );
        }
        let source_paths =
            crate::value_contract::encoded::comparison_paths(&source.logical, rules)?
                .into_iter()
                .chain(paths.iter().cloned())
                .collect::<Vec<_>>();
        let target_paths =
            crate::value_contract::encoded::comparison_paths(&target.logical, rules)?
                .into_iter()
                .chain(paths.iter().cloned())
                .collect::<Vec<_>>();
        self.compare_values_global(
            &source.comparison_value(&source_paths),
            &target.comparison_value(&target_paths),
            rules,
            global,
            clocks,
        )
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.generated.is_empty()
            && self.jwt.is_empty()
            && self.fields.is_empty()
            && self.joined.is_empty()
            && self.codec.is_none()
    }

    pub(crate) fn rule_ids(&self) -> Vec<String> {
        self.generated
            .iter()
            .map(|field| field.id.clone())
            .chain(self.jwt.iter().map(|field| field.id.clone()))
            .chain(self.fields.iter().map(|(id, _, _)| id.clone()))
            .chain(self.joined.iter().map(|(id, _, _)| id.clone()))
            .chain(self.codec_ids.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub(crate) fn key_witnesses(&self) -> impl Iterator<Item = &(PathBuf, String)> {
        self.jwt
            .iter()
            .chain(&self.header_jwt)
            .flat_map(|field| field.key.witnesses())
            .chain(
                self.generated
                    .iter()
                    .filter_map(|field| field.key.as_ref())
                    .flat_map(EncryptionKeySnapshot::witnesses),
            )
    }

    pub(crate) fn ensure_current(&self) -> Result<()> {
        for field in &self.generated {
            if let Some(key) = &field.key {
                key.ensure_current()?;
            }
        }
        for field in self.jwt.iter().chain(&self.header_jwt) {
            field.key.ensure_current()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn compare_json(
        &self,
        source: &Value,
        target: &Value,
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        anyhow::ensure!(
            self.payload_codec(rules)? == crate::policy::Codec::Json,
            "JSON comparison requires a JSON codec"
        );
        self.compare_values(source, target, rules, clocks)
    }

    #[cfg(test)]
    fn compare_values(
        &self,
        source: &Value,
        target: &Value,
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        self.compare_values_global(source, target, rules, None, clocks)
    }

    fn compare_values_global(
        &self,
        source: &Value,
        target: &Value,
        rules: &[&CompiledRule],
        global: Option<&crate::policy::CompiledJsonPolicy>,
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        self.ensure_current()?;
        let global_fields = global
            .map(|plan| plan.comparison_fields(source, target, clocks))
            .transpose()?
            .unwrap_or_default();
        let mut fields = rules
            .iter()
            .flat_map(|rule| {
                rule.rule
                    .contract
                    .iter()
                    .map(move |(pointer, contract)| Field {
                        rule_id: &rule.rule.id,
                        pointer,
                        contract,
                    })
            })
            .collect::<Vec<_>>();
        fields.extend(self.fields.iter().map(|(id, pointer, contract)| Field {
            rule_id: id,
            pointer,
            contract,
        }));
        for (pointer, contract) in &global_fields {
            if !fields
                .iter()
                .any(|field| field.pointer == pointer && field.contract == contract)
            {
                fields.push(Field {
                    rule_id: crate::policy::GLOBAL_JSON_ID,
                    pointer,
                    contract,
                });
            }
        }
        let generated = self
            .generated
            .iter()
            .map(|field| NativeField {
                rule_id: &field.id,
                pointer: &field.pointer,
                contract: &field.contract,
                key: field.key.as_ref().map(EncryptionKeySnapshot::bytes),
            })
            .collect::<Vec<_>>();
        type Verifier<'a> =
            Box<dyn Fn(LeafContext<'_>) -> std::result::Result<LeafObservations, String> + 'a>;
        let mut callbacks = Vec::<(&str, &str, Verifier<'_>)>::new();
        for field in &self.jwt {
            let rule = &field.rule;
            for pointer in std::iter::once(rule.pointer.as_str())
                .chain(rule.companion_pointers())
                .chain(rule.ttl.iter().map(String::as_str))
            {
                let token = pointer == rule.pointer;
                callbacks.push((
                    &field.id,
                    pointer,
                    Box::new(move |context| {
                        let source_pointer =
                            crate::replay::policy::ResponseJwtRule::concrete_pointer(
                                &rule.pointer,
                                context.source_pointer,
                            );
                        let target_pointer =
                            crate::replay::policy::ResponseJwtRule::concrete_pointer(
                                &rule.pointer,
                                context.target_pointer,
                            );
                        let source = context
                            .source_root
                            .pointer(&source_pointer)
                            .ok_or_else(|| "signed Source token is absent".to_string())?;
                        let target = context
                            .target_root
                            .pointer(&target_pointer)
                            .ok_or_else(|| "signed Target token is absent".to_string())?;
                        let validated = super::jwt::compare(
                            rule,
                            source,
                            target,
                            context.clocks.case,
                            &field.key.bytes,
                            field.key.kid.as_deref(),
                        )
                        .map_err(|error| {
                            format!("authenticated JWT contract rejected: {error:?}")
                        })?;
                        super::jwt::companions::compare_pair(
                            rule,
                            [context.source_pointer, context.target_pointer],
                            [context.source_root, context.target_root],
                            &validated,
                        )
                        .map_err(|error| {
                            format!("authenticated JWT companion rejected: {error:?}")
                        })?;
                        if rule.ttl.as_deref() == Some(pointer) && context.source != context.target
                        {
                            return Err("JWT TTL is a stable business value".into());
                        }
                        Ok(LeafObservations {
                            time_validations: if token { validated.time_validations } else { 0 },
                            identities: if token {
                                std::iter::once(
                                    super::jwt::identity_pair(rule, source, target).map_err(
                                        |error| format!("JWT identity rejected: {error:?}"),
                                    )?,
                                )
                                .chain(validated.nonces.iter().map(|nonce| {
                                    crate::value_contract::identities::IdentityPair {
                                        source: serde_json::to_string(&nonce.source)
                                            .expect("validated nonce string"),
                                        target: serde_json::to_string(&nonce.target)
                                            .expect("validated nonce string"),
                                    }
                                }))
                                .collect()
                            } else {
                                vec![]
                            },
                            nonces: if token {
                                validated
                                    .nonces
                                    .into_iter()
                                    .map(|nonce| {
                                        NonceIdentity::new(
                                            nonce.claim,
                                            &nonce.source,
                                            &nonce.target,
                                        )
                                    })
                                    .collect()
                            } else {
                                vec![]
                            },
                        })
                    }),
                ));
            }
        }
        for (id, pointer, separator) in &self.joined {
            callbacks.push((
                id,
                pointer,
                Box::new(move |context| {
                    let (Some(source), Some(target)) =
                        (context.source.as_str(), context.target.as_str())
                    else {
                        return Err("joined collection requires two strings".into());
                    };
                    if !super::joined_string::equal(source, target, separator) {
                        return Err("joined multiset changed".into());
                    }
                    Ok(LeafObservations::default())
                }),
            ));
        }
        let mut verified = callbacks
            .iter()
            .map(|(id, pointer, verifier)| VerifiedField {
                rule_id: id,
                pointer,
                verifier: verifier.as_ref(),
            })
            .collect::<Vec<_>>();
        let protocol_checks = global
            .map(|plan| crate::value_contract::global_protocol::checks(plan, source))
            .transpose()?;
        if let Some(checks) = &protocol_checks {
            verified.extend(checks.fields());
        }
        let mut result =
            json::compare_with_verified(source, target, &fields, &generated, &verified, clocks);
        if !global_fields.is_empty() {
            result
                .evaluated
                .insert(crate::policy::GLOBAL_JSON_ID.into());
        }
        result.evaluated.extend(self.codec_ids.iter().cloned());
        Ok(result)
    }
}

pub(crate) fn source_request_body(request: &Value) -> Option<Value> {
    crate::replay::policy::case_condition::request_body(request)
}
