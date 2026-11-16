//! Typed native effects reuse domain runtimes without a legacy document codec.
use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::policy::native as n;
use crate::policy::{CompiledNativeRule, SourceCondition};

use super::config::{
    DependencyProtocol, ExpectedResponseUsage, ReplayDependencyRule, ReplayPolicyDocument,
    ReplayScope, TargetSelector,
};

mod dependency;
pub(crate) use dependency::generated;
mod identity;
mod response;
pub(crate) use response::{dynamic_claim, project_jwt};
pub(crate) use traffic_policy_schema::scope::NativeScopeGuard;
mod native_admission;
mod source;
mod source_validation;
pub(crate) use source::validate_finite_sharing;
pub(crate) use source_validation::{NativeSourceCase, validate_native_source_dependencies};

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
            n::NativeEffect::Identity(_) if n::is_key_only_read_back(rule) => {
                // Key-only read state uses globally declared scalar identities
                // and the causal write ledger, with no legacy capture model.
            }
            n::NativeEffect::Identity(effect) => output
                .document
                .dynamic_values
                .push(identity::project(rule, effect)?),
            n::NativeEffect::RedisSequence(_)
            | n::NativeEffect::HttpRequest(_)
            | n::NativeEffect::MysqlValues(_)
            | n::NativeEffect::FiniteSharing(_) => output
                .document
                .dependency_rules
                .push(dependency::project(rule)?),
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

fn dependency_rule(rule: &n::NativeRule) -> Result<ReplayDependencyRule> {
    let resource = rule.selector.resource.as_ref();
    let protocol = resource
        .map(|resource| resource.protocol)
        .or(match &rule.effect {
            n::NativeEffect::RedisSequence(_)
            | n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis { .. }) => {
                Some(crate::policy::Protocol::Redis)
            }
            n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http) => {
                Some(crate::policy::Protocol::Http)
            }
            _ => None,
        })
        .context("native dependency has no resource or protocol owner")?;
    Ok(ReplayDependencyRule {
        id: rule.id.clone(),
        when: condition(rule.when.as_ref()),
        replay_scope: ReplayScope::Case,
        source_evidence: String::new(),
        case_selector: rule
            .selector
            .api
            .as_deref()
            .map(|api| -> Result<super::config::CaseSelector> {
                let (method, path) = api
                    .split_once(' ')
                    .context("invalid compiled API selector")?;
                Ok(super::config::CaseSelector {
                    method: method.into(),
                    path: path.into(),
                })
            })
            .transpose()?,
        protocol: match protocol {
            crate::policy::Protocol::Http => DependencyProtocol::Http,
            crate::policy::Protocol::Redis => DependencyProtocol::Redis,
            crate::policy::Protocol::Memcached => DependencyProtocol::Memcached,
            crate::policy::Protocol::Mysql => DependencyProtocol::Mysql,
        },
        target: TargetSelector {
            host: resource
                .map(|resource| resource.endpoint.host.clone())
                .or_else(|| rule.selector.http_host.clone()),
            port: resource.map(|resource| resource.endpoint.port),
        },
        mysql: None,
        http: None,
        memcached: None,
        redis: None,
    })
}

pub(crate) fn key(value: &n::NativeKeySelector) -> crate::RedisValueKeySelector {
    match value {
        n::NativeKeySelector::Exact { value } => crate::RedisValueKeySelector::Exact {
            value: value.clone(),
        },
        n::NativeKeySelector::Affix { prefix, suffix } => crate::RedisValueKeySelector::Affix {
            prefix: prefix.clone(),
            suffix: suffix.clone(),
        },
        n::NativeKeySelector::Numeric { prefix, suffix } => crate::RedisValueKeySelector::Numeric {
            prefix: prefix.clone(),
            suffix: suffix.clone(),
        },
    }
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

fn condition(value: Option<&SourceCondition>) -> Option<super::case_condition::CaseCondition> {
    value.map(|condition| super::case_condition::CaseCondition {
        request_body_json: condition
            .request_body_json
            .iter()
            .map(|(pointer, predicate)| {
                let predicate = match predicate {
                    crate::policy::SourcePredicate::Equals(value) => {
                        super::case_condition::JsonCondition::Equals(scalar(&value.equals))
                    }
                    crate::policy::SourcePredicate::NotEquals(value) => {
                        super::case_condition::JsonCondition::NotEquals(scalar(&value.not_equals))
                    }
                };
                (pointer.clone(), predicate)
            })
            .collect(),
    })
}

fn scalar(value: &crate::policy::SourceScalar) -> serde_json::Value {
    match value {
        crate::policy::SourceScalar::Null => serde_json::Value::Null,
        crate::policy::SourceScalar::Bool(value) => (*value).into(),
        crate::policy::SourceScalar::Number(value) => value.clone().into(),
        crate::policy::SourceScalar::String(value) => value.clone().into(),
    }
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
