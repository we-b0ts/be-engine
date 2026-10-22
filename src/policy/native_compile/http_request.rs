//! HTTP request field admission keeps signed bodies separate from transport identity.
use super::*;

pub(super) fn validate_client_metadata(
    selector: &NativeMatch,
    effect: &HttpClientMetadataEffect,
) -> Result<()> {
    resource(selector, Protocol::Http)?;
    ensure!(
        selector.operation.is_some() && selector.path.is_some(),
        "HTTP client metadata requires an explicit method and consumer path"
    );
    hyper::Method::from_bytes(selector.operation.as_deref().unwrap().as_bytes())?;
    ensure!(
        !effect.headers.is_empty() && effect.headers.len() <= HTTP_CLIENT_METADATA_HEADERS.len(),
        "HTTP client metadata requires 1..=9 exact SDK header names"
    );
    let mut names = BTreeSet::new();
    for name in &effect.headers {
        ensure!(
            HTTP_CLIENT_METADATA_HEADERS.contains(&name.as_str()) && names.insert(name),
            "HTTP client metadata requires unique lowercase supported SDK names: {name:?}"
        );
    }
    Ok(())
}

pub(super) fn validate(selector: &NativeMatch, effect: &HttpRequestEffect) -> Result<()> {
    resource(selector, Protocol::Http)?;
    ensure!(
        selector.operation.is_some() && selector.path.is_some(),
        "HTTP request effect requires method and path"
    );
    ensure!(
        !effect.headers.is_empty()
            || !effect.query.is_empty()
            || !effect.json.is_empty()
            || effect.multipart_boundary,
        "HTTP request effect has no contract"
    );
    ensure!(
        !effect.multipart_boundary || effect.json.is_empty(),
        "multipart boundary and JSON body contracts require separate body codecs"
    );
    for (name, time) in &effect.headers {
        hyper::header::HeaderName::from_bytes(name.as_bytes())?;
        proven(time, validate_time)?;
    }
    for (name, value) in &effect.query {
        text(name, "query parameter", 128)?;
        proven(value, validate_generated_value)?;
    }
    ensure!(
        effect.json.len() <= 32,
        "HTTP JSON accepts at most 32 fields"
    );
    for (pointer, field) in &effect.json {
        compiler::validate_pointer(pointer, false)?;
        ensure!(!pointer.is_empty(), "HTTP JSON requires non-root pointers");
        ensure!(
            effect.json.keys().all(|other| pointer == other
                || !pointer
                    .split('/')
                    .zip(other.split('/'))
                    .all(|(a, b)| a == b)),
            "HTTP JSON fields overlap"
        );
        proven(field, |field| match field {
            HttpJsonField::Random { format, length } => {
                crate::value_contract::generated::validate_bounded_random(
                    format,
                    Some(*length),
                    None,
                )
            }
            HttpJsonField::Jwt {
                algorithm,
                signing_key,
                anchor,
                nonces,
            } => {
                ensure!(
                    *algorithm != SignatureAlgorithm::RS256,
                    "HTTP request JWT requires a startup HMAC key"
                );
                ensure!(
                    *anchor == crate::policy::TimeAnchor::DependencyRequestStart,
                    "HTTP request JWT uses the corresponding dependency request start"
                );
                validate_startup_key(signing_key)?;
                ensure!(
                    nonces.len() <= 2,
                    "HTTP request JWT accepts at most two nonce claims"
                );
                let mut claims = BTreeSet::new();
                for nonce in nonces {
                    proven(nonce, validate_nonce)?;
                    ensure!(
                        claims.insert(&nonce.contract.pointer),
                        "duplicate HTTP request JWT nonce claim"
                    );
                }
                Ok(())
            }
        })?;
    }
    Ok(())
}
