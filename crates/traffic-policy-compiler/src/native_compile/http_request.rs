//! HTTP request field admission keeps signed bodies separate from transport identity.
use super::*;

pub fn validate(selector: &NativeMatch, effect: &HttpRequestEffect) -> Result<()> {
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
