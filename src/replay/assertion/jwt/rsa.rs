//! Response-only RS256 authentication; never re-sign or transform a token.
use crate::request_rules::jwt::contract::{self, Failure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use x509_parser::prelude::FromDer;

fn authenticate(
    value: &Value,
    key: &jsonwebtoken::DecodingKey,
    kid: Option<&str>,
) -> Result<(Value, Value), Failure> {
    let raw = value
        .as_str()
        .filter(|v| v.len() <= 64 * 1024)
        .ok_or(Failure::Invalid)?;
    let parts = raw.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Failure::Invalid);
    }
    let json = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| crate::json_value::parse(&bytes))
            .ok_or(Failure::Invalid)
    };
    let header = json(parts[0])?;
    let claims = json(parts[1])?;
    if !header.is_object()
        || !claims.is_object()
        || header.get("crit").is_some()
        || header.get("b64").is_some()
    {
        return Err(Failure::Invalid);
    }
    if header["alg"] != "RS256" {
        return Err(Failure::Algorithm);
    }
    if kid.is_some_and(|kid| header["kid"].as_str() != Some(kid)) {
        return Err(Failure::Claims);
    }
    if !jsonwebtoken::crypto::verify(
        parts[2],
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        key,
        jsonwebtoken::Algorithm::RS256,
    )
    .unwrap_or(false)
    {
        return Err(Failure::Signature);
    }
    Ok((header, claims))
}

pub(super) fn compare(
    source: &Value,
    target: &Value,
    key: &[u8],
    kid: Option<&str>,
    anchors: [i128; 2],
    dynamic: &[crate::request_rules::JwtDynamicClaim],
) -> Result<contract::Validated, Failure> {
    let mut reader = key;
    let Some(rustls_pemfile::Item::SubjectPublicKeyInfo(der)) =
        rustls_pemfile::read_one(&mut reader).map_err(|_| Failure::Signature)?
    else {
        return Err(Failure::Signature);
    };
    if rustls_pemfile::read_one(&mut reader)
        .map_err(|_| Failure::Signature)?
        .is_some()
    {
        return Err(Failure::Signature);
    }
    let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der.as_ref())
        .map_err(|_| Failure::Signature)?;
    if !rest.is_empty() || spki.algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.1" {
        return Err(Failure::Signature);
    }
    let key = jsonwebtoken::DecodingKey::from_rsa_der(&spki.subject_public_key.data);
    let (source_header, source) = authenticate(source, &key, kid)?;
    let (target_header, target) = authenticate(target, &key, kid)?;
    if source_header != target_header {
        return Err(Failure::Claims);
    }
    contract::compare_authenticated_claims(source, target, anchors, 5_000_000_000, dynamic)
}
