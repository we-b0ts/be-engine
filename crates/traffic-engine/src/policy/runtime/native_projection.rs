//! Typed native effects reuse domain runtimes without a legacy document codec.
use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::policy::CompiledNativeRule;
use crate::policy::native as n;

use super::config::{ExpectedResponseUsage, ReplayPolicyDocument};

mod response;
mod response_format;
pub(crate) use response::project_jwt;
pub(crate) use traffic_policy_schema::scope::NativeScopeGuard;
mod input_validation;
mod native_admission;
pub use input_validation::{SourceInputCase, validate_source_inputs};

#[derive(Debug)]
pub(crate) struct NativeRuntimeProjection {
    pub document: ReplayPolicyDocument,
    /// Domain owner ids are projected back to the complete user rule in reports.
    pub response_aliases: BTreeMap<String, String>,
}

/// Compiler admission and runtime construction share this typed adapter.
/// It performs no I/O, secret resolution or payload comparison.
pub(crate) fn validate_native_adapter(rule: &CompiledNativeRule) -> Result<()> {
    project_native(std::slice::from_ref(rule))?;
    Ok(())
}

pub(crate) fn project_native(rules: &[CompiledNativeRule]) -> Result<NativeRuntimeProjection> {
    let mut output = NativeRuntimeProjection {
        document: ReplayPolicyDocument {
            version: 3,
            expected_response: ExpectedResponseUsage::AssertionsOnly,
            dynamic_values: vec![],
            dependency_rules: vec![],
            request_rules: crate::request_rules::RequestRules::default(),
            response_rules: super::response::ResponseRules::default(),
        },
        response_aliases: BTreeMap::new(),
    };
    for compiled in rules {
        let rule = &compiled.rule;
        native_admission::validate(rule)?;
        match &rule.effect {
            n::NativeEffect::Identity(_)
            | n::NativeEffect::RedisSequence(_)
            | n::NativeEffect::HttpRequest(_)
            | n::NativeEffect::MysqlValues(_)
            | n::NativeEffect::FiniteSharing(_) => {
                unreachable!("unavailable native effects are rejected before projection")
            }
            n::NativeEffect::ResponseJwt(_)
            | n::NativeEffect::ResponseHeaderDate(_)
            | n::NativeEffect::ResponseBody(_) => response::project(&mut output, rule)?,
            n::NativeEffect::ResponseGenerated(_) => (),
            // Native protocol owners consume these typed effects directly.
            n::NativeEffect::RedisAppendStream
            | n::NativeEffect::RedisReadCommutation(_)
            | n::NativeEffect::RedisReadObservation(_)
            | n::NativeEffect::RedisExpiryRefresh(_)
            | n::NativeEffect::RedisActivityRefresh(_) => (),
            n::NativeEffect::InputJwt(effect) => input(&mut output, rule, effect)?,
            // The inbound runtime consumes this typed effect directly; no
            // legacy request-rule document represents custom signatures.
            n::NativeEffect::InputSignedTimestamp(_) => (),
            n::NativeEffect::CaptureHttp(_)
            | n::NativeEffect::CaptureBreeze(_)
            | n::NativeEffect::CaptureHttpResponse(_)
            | n::NativeEffect::ProcessOwned(_) => continue,
        }
    }
    Ok(output)
}

pub(crate) fn startup_key(value: &n::StartupKey) -> crate::request_rules::keys::SigningKeySource {
    match value {
        n::StartupKey::TargetEnv { name } => {
            crate::request_rules::keys::SigningKeySource::TargetEnv { name: name.clone() }
        }
        n::StartupKey::TargetFile { path, field } => {
            crate::request_rules::keys::SigningKeySource::TargetFile {
                path: path.into(),
                field: field.clone(),
            }
        }
    }
}

pub(crate) fn hmac_algorithm(
    value: n::SignatureAlgorithm,
) -> Result<crate::request_rules::JwtAlgorithm> {
    Ok(match value {
        n::SignatureAlgorithm::HS256 => crate::request_rules::JwtAlgorithm::HS256,
        n::SignatureAlgorithm::HS384 => crate::request_rules::JwtAlgorithm::HS384,
        n::SignatureAlgorithm::HS512 => crate::request_rules::JwtAlgorithm::HS512,
        n::SignatureAlgorithm::RS256 => anyhow::bail!(
            "request execution cannot consume recorded public keys or RS256 signing keys"
        ),
    })
}

fn input(
    output: &mut NativeRuntimeProjection,
    rule: &n::NativeRule,
    effect: &n::InputJwtEffect,
) -> Result<()> {
    let profile = format!(
        "native_{}",
        crate::policy::digest("traffic-policy/input-profile/v1", &rule.id)?
            .trim_start_matches("sha256:")
    );
    output.document.request_rules.jwt.profiles.insert(
        profile.clone(),
        crate::request_rules::JwtProfile {
            signing_key_ref: profile.clone(),
            signing_key_source: Some(startup_key(&effect.signing_key)),
            algorithm: hmac_algorithm(effect.algorithm)?,
            time: crate::request_rules::JwtTime::PreserveRelative,
        },
    );
    let (header, scheme, query_param, socketio_connect) = match &effect.location {
        n::InputTokenLocation::BearerHeader { name } => {
            (Some(name.clone()), Some("bearer".into()), None, None)
        }
        n::InputTokenLocation::RawHeader { name } => {
            (Some(name.clone()), Some("raw".into()), None, None)
        }
        n::InputTokenLocation::Query { name } => (None, None, Some(name.clone()), None),
        n::InputTokenLocation::SocketIoConnect { namespace, pointer } => (
            None,
            None,
            None,
            Some(crate::request_rules::SocketIoConnectLocation {
                namespace: namespace.clone(),
                pointer: pointer.clone(),
            }),
        ),
    };
    output
        .document
        .request_rules
        .jwt
        .rules
        .push(crate::request_rules::JwtRule {
            id: rule.id.clone(),
            header,
            scheme,
            query_param,
            socketio_connect,
            profile,
        });
    output.document.request_rules.validate()?;
    Ok(())
}

fn proof(value: Option<&crate::policy::Proof>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    use sha2::{Digest, Sha256};
    // The domain projection carries only a compact lookup certificate. Complete
    // inline proof remains in the compiled rule and every plan artifact.
    let mut hash = Sha256::new();
    hash.update(value.source.as_bytes());
    hash.update([0]);
    hash.update(value.fact.as_bytes());
    format!("traffic-policy inline proof sha256:{:x}", hash.finalize())
}

pub(crate) fn compiled_input_rules(
    compiled: &crate::policy::CompiledPolicy,
) -> Result<crate::request_rules::RequestRules> {
    Ok(project_native(&compiled.native)?.document.request_rules)
}

/// Finite sharing has no installed execution capability in this runtime.
pub(crate) fn validate_finite_sharing(
    _case_source: &std::path::Path,
    _replay_report: &std::path::Path,
    _compiled: &CompiledNativeRule,
) -> Result<usize> {
    anyhow::bail!("finite sharing requires an installed native sharing capability")
}
