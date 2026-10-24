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
        !effect.query.is_empty() || effect.multipart_boundary,
        "HTTP request effect has no contract"
    );
    for (name, value) in &effect.query {
        text(name, "query parameter", 128)?;
        proven(value, validate_generated_value)?;
    }
    Ok(())
}
