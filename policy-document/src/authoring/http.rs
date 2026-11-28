//! HTTP route declarations lower to existing acquisition and identity owners.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use crate::native::{
    CapturePath, CaptureResponseContract, CaptureResponseEffect, IdentityCapture, IdentityEffect,
    IdentityTarget, IdentityType, PathIdentityField, PathIdentitySegment, PathRandomFormat,
    PathTimestampMode, Proven,
};
use crate::{
    Endpoint, HttpPolicy, NativeEffect, NativeMatch, NativeRule, PolicyRule, Proof, Protocol,
    Resource, ResourceDeclaration,
};

pub mod declarations;
pub mod reverse;
pub use declarations::HttpDocument;
use declarations::*;

pub const PREFIX: &str = "http.request.";

pub fn inherit(own: Option<&Proof>, parent: Option<&Proof>) -> Result<Option<Proof>> {
    let own = own.map(serde_yaml::to_value).transpose()?;
    let parent = parent.map(serde_yaml::to_value).transpose()?;
    let proof = super::proof::expand(own, parent.as_ref(), None)?;
    if proof.is_null() {
        Ok(None)
    } else {
        serde_yaml::from_value(proof).map(Some).map_err(Into::into)
    }
}

pub fn host(raw: &str) -> Result<String> {
    ensure!(
        !raw.is_empty()
            && raw.len() <= 512
            && !raw.chars().any(char::is_whitespace)
            && !raw.contains(['@', '/', '?', '#', '*']),
        "HTTP request host requires one bounded literal authority"
    );
    raw.parse::<hyper::http::uri::Authority>()?;
    Ok(raw.to_ascii_lowercase())
}

pub fn reference(
    reference: &ResourceReference,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> Result<Resource> {
    match reference {
        ResourceReference::Name(name) => named
            .get(name)
            .map(|definition| definition.resource.clone())
            .with_context(|| format!("unknown HTTP identity resource reference {name:?}")),
        ResourceReference::Physical(resource) => Ok(resource.clone()),
    }
}

pub fn path_field(field: &PathField) -> PathIdentityField {
    match field {
        PathField::Exact(_) => PathIdentityField::Exact,
        PathField::Hex { hex } => PathIdentityField::Random {
            format: PathRandomFormat::Hex,
            length: *hex,
        },
        PathField::Timestamp {
            timestamp,
            timezone,
            mode,
        } => PathIdentityField::Timestamp {
            format: timestamp.clone(),
            timezone: timezone.clone(),
            mode: *mode,
        },
    }
}

pub fn identity(
    entry: &Request,
    authority: &str,
    method: &str,
    identity: &PathIdentity,
    named: &BTreeMap<String, ResourceDeclaration>,
) -> Result<(NativeMatch, NativeEffect, Option<Proof>)> {
    let endpoint = Endpoint::parse(authority)
        .context("HTTP path identity host requires an explicit physical port")?;
    ensure!(
        (1..=32).contains(&identity.fields.len()) && (1..=32).contains(&identity.references.len()),
        "HTTP path identity requires 1..32 fields and reference resources"
    );
    let proof = inherit(identity.proof.as_ref(), entry.proof.as_ref())?;
    let fields = identity
        .fields
        .iter()
        .map(|(name, value)| {
            let (field, local) = value.parts();
            Ok((
                name.clone(),
                Proven {
                    contract: path_field(field),
                    proof: inherit(local, proof.as_ref())?,
                },
            ))
        })
        .collect::<Result<_>>()?;
    let mut references = Vec::with_capacity(identity.references.len());
    let mut seen = BTreeSet::new();
    for value in &identity.references {
        let (selected, local) = value.parts();
        let resource = reference(selected, named)?;
        ensure!(
            seen.insert(serde_json::to_vec(&resource)?),
            "duplicate HTTP identity reference resource"
        );
        references.push(Proven {
            contract: IdentityTarget { resource },
            proof: inherit(local, proof.as_ref())?,
        });
    }
    Ok((
        NativeMatch {
            api: entry.api.clone(),
            resource: Some(Resource {
                protocol: Protocol::Http,
                endpoint,
                database: None,
                username: None,
            }),
            operation: Some(method.into()),
            path: Some(entry.path.clone()),
            ..Default::default()
        },
        NativeEffect::Identity(IdentityEffect {
            value_type: IdentityType::String,
            format: None,
            capture: IdentityCapture::HttpPath {
                segment: PathIdentitySegment {
                    index: identity.segment,
                    template: identity.template.clone(),
                    fields,
                },
            },
            references,
        }),
        proof,
    ))
}

pub fn capture(
    entry: &Request,
    authority: &str,
    method: &str,
    capture: &Capture,
) -> Result<(NativeMatch, NativeEffect, Option<Proof>)> {
    ensure!(
        entry.api.is_none(),
        "HTTP response URL capture cannot select an inbound API"
    );
    ensure!(
        capture.capture_urls.len() <= 128
            && capture.status_codes.len() <= 500
            && capture.content_types.len() <= 64,
        "HTTP response capture exceeds URL, status or content-type bounds"
    );
    ensure!(
        usize::from(!capture.capture_urls.is_empty())
            + usize::from(!capture.documents.is_empty())
            + usize::from(capture.policy.is_some())
            == 1,
        "response rewrite requires exactly one json_urls, documents or policy declaration"
    );
    let proof = inherit(entry.proof.as_ref(), None)?;
    let mut seen = BTreeSet::new();
    let pointers = capture
        .capture_urls
        .iter()
        .map(|value| {
            let (pointer, local) = value.parts();
            ensure!(
                seen.insert(pointer.clone()),
                "duplicate HTTP capture URL pointer"
            );
            Ok(Proven {
                contract: pointer.clone(),
                proof: inherit(local, proof.as_ref())?,
            })
        })
        .collect::<Result<_>>()?;
    ensure!(
        capture.status_codes.iter().collect::<BTreeSet<_>>().len() == capture.status_codes.len()
            && capture
                .content_types
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect::<BTreeSet<_>>()
                .len()
                == capture.content_types.len(),
        "duplicate HTTP capture status or content type"
    );
    Ok((
        NativeMatch::default(),
        NativeEffect::CaptureHttpResponse(CaptureResponseEffect {
            authorities: vec![authority.into()],
            methods: vec![method.into()],
            path: if entry.path.contains('*') {
                CapturePath::Pattern {
                    value: entry.path.clone(),
                }
            } else {
                CapturePath::Exact {
                    value: entry.path.clone(),
                }
            },
            status_codes: capture.status_codes.clone(),
            content_types: capture.content_types.clone(),
            contract: if let Some(definition) = &capture.policy {
                CaptureResponseContract::Policy(definition.clone())
            } else if capture.documents.is_empty() {
                CaptureResponseContract::Urls { pointers }
            } else {
                CaptureResponseContract::Documents {
                    rules: capture.documents.clone(),
                }
            },
        }),
        proof,
    ))
}

pub fn without_proofs(mut rule: NativeRule) -> NativeRule {
    rule.proof = None;
    match &mut rule.effect {
        NativeEffect::Identity(effect) => {
            for reference in &mut effect.references {
                reference.proof = None;
            }
            if let IdentityCapture::HttpPath { segment } = &mut effect.capture {
                for field in segment.fields.values_mut() {
                    field.proof = None;
                }
            }
        }
        NativeEffect::CaptureHttpResponse(effect) => {
            if let CaptureResponseContract::Urls { pointers } = &mut effect.contract {
                for pointer in pointers {
                    pointer.proof = None;
                }
            }
        }
        _ => (),
    }
    rule
}

pub fn lower(
    entry: &Request,
    named: &BTreeMap<String, ResourceDeclaration>,
    context: &crate::AuthoringContext<'_>,
) -> Result<NativeRule> {
    let authority = host(&entry.host)?;
    let method = entry.method.to_ascii_uppercase();
    hyper::Method::from_bytes(method.as_bytes())?;
    ensure!(
        entry.path.len() <= 2048,
        "HTTP request path exceeds 2048 bytes"
    );
    traffic_protocol_http::path_pattern::validate_path_selector(&entry.path)?;
    ensure!(
        entry.path_identity.is_some() != entry.response.is_some(),
        "HTTP request requires exactly one path_identity or response capture"
    );
    let (selector, effect, proof) = if let Some(value) = &entry.path_identity {
        identity(entry, &authority, &method, value, named)?
    } else {
        capture(
            entry,
            &authority,
            &method,
            entry.response.as_ref().expect("checked capture"),
        )?
    };
    let mut rule = NativeRule {
        id: String::new(),
        selector,
        effect,
        proof,
        when: None,
    };
    let semantic = without_proofs(rule.clone());
    let hash = Sha256::digest(serde_json::to_vec(&(semantic.selector, semantic.effect))?);
    rule.id = entry
        .response
        .as_ref()
        .and_then(|capture| capture.name.clone())
        .unwrap_or_else(|| format!("{PREFIX}{hash:x}"));
    context.compile_native(&rule)?;
    Ok(rule)
}

pub fn position(entry: &Request) -> Result<(String, String, String, Option<String>, bool)> {
    Ok((
        host(&entry.host)?,
        entry.method.to_ascii_uppercase(),
        entry.path.clone(),
        entry.api.clone(),
        entry.path_identity.is_some(),
    ))
}

pub fn expand(
    document: Option<HttpDocument>,
    named: &BTreeMap<String, ResourceDeclaration>,
    context: &crate::AuthoringContext<'_>,
) -> Result<(Option<HttpPolicy>, Vec<Value>)> {
    let Some(document) = document else {
        return Ok((None, vec![]));
    };
    let entry_count = document.requests.len() + document.response_rewrite.len();
    ensure!(
        entry_count <= 4096,
        "HTTP requests and response rewrites exceed 4096 entries"
    );
    let mut request_sigv4 = Vec::new();
    let mut entries = Vec::with_capacity(entry_count);
    for request in document.requests {
        match request {
            RequestDeclaration::PathIdentity(path) => entries.push(Request::from(path)),
            RequestDeclaration::SigV4(rule) => request_sigv4.push(rule),
        }
    }
    entries.extend(document.response_rewrite.into_iter().map(Request::from));
    let http = if document.headers.is_some()
        || !document.request_metadata.is_empty()
        || !request_sigv4.is_empty()
        || entry_count == 0
    {
        Some(
            HttpPolicy {
                headers: document.headers.unwrap_or_default(),
                request_metadata: document.request_metadata,
                request_sigv4,
            }
            .compile(context)?,
        )
    } else {
        None
    };
    let mut positions = BTreeSet::new();
    let mut rules = Vec::with_capacity(entries.len());
    for entry in entries {
        ensure!(
            positions.insert(position(&entry)?),
            "duplicate HTTP request position"
        );
        rules.push(serde_yaml::to_value(lower(&entry, named, context)?)?);
    }
    Ok((http, rules))
}

pub fn generated(rule: &PolicyRule) -> bool {
    rule.id().starts_with(PREFIX)
}

pub fn compact(
    rule: &PolicyRule,
    named: &BTreeMap<String, ResourceDeclaration>,
    root: &mut Mapping,
    context: &crate::AuthoringContext<'_>,
) -> Result<bool> {
    reverse::compact(rule, named, root, context)
}
