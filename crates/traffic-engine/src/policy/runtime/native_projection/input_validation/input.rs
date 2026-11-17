//! Verify the immutable input token with the same startup key and JWS owner.
use super::*;
use crate::request_rules::{jwt, keys::ResolvedSigningKey};

pub(super) fn validate(
    compiled: &CompiledPolicy,
    root: &Path,
    case: &SourceInputCase<'_>,
    checked: &mut SourceInputValidation,
) -> Result<()> {
    let body = super::super::super::case_condition::request_body(case.request);
    let path = super::super::super::pattern::uri_path(
        case.request["uri"]
            .as_str()
            .context("Source input URI is absent")?,
    );
    let rules = compiled
        .native
        .iter()
        .filter(|compiled| {
            matches!(compiled.rule.effect, NativeEffect::InputJwt(_))
                && NativeScopeGuard::from_rule(&compiled.rule).matches_case(
                    case.request["method"].as_str().unwrap_or_default(),
                    &path,
                    body.as_ref(),
                )
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return Ok(());
    }
    // The caller may hold the protected recording or its decrypted Source view.
    // Accept neither an edited request nor a Target-generated token as Source.
    let (original, decrypted) =
        crate::request_headers::read_request_file_parts(&case.dir.join("request.json"))?;
    let original: Value = serde_json::from_slice(&original)?;
    let source = decrypted
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()?
        .unwrap_or_else(|| original.clone());
    ensure!(
        *case.request == original || *case.request == source,
        "Source input request differs from its immutable recording"
    );
    jwt::request_timestamp(&source)?;
    for compiled in rules {
        let projection = project_native(std::slice::from_ref(compiled))?;
        let config = &projection.document.request_rules.jwt;
        let rule = config
            .rules
            .first()
            .context("native input rule was not projected")?;
        let profile = config
            .profiles
            .get(&rule.profile)
            .context("native input profile missing")?;
        let Some(raw) = jwt::request_token(&source, &rule.location()?)? else {
            continue;
        };
        let Some(token) = jwt::Token::parse(&raw)? else {
            continue;
        };
        if token.algorithm != profile.algorithm || !token.has_time_claims() {
            continue;
        }
        let key = ResolvedSigningKey::resolve(
            root,
            profile
                .signing_key_source
                .as_ref()
                .context("native input key source missing")?,
        )?;
        if !token.verify(key.bytes()) {
            continue;
        }
        let claims = token.claims.clone();
        let header = token.header_value()?;
        let shifted = token.shift(0, key.bytes())?;
        let shifted =
            jwt::Token::parse(&shifted)?.context("Source input self translation is invalid")?;
        ensure!(
            shifted.claims == claims
                && shifted.header_value()? == header
                && shifted.verify(key.bytes()),
            "Source input self translation changed an unselected claim or header"
        );
        key.ensure_current()?;
        checked.key_witnesses.extend(key.witnesses().cloned());
        *checked.rules.entry(compiled.rule.id.clone()).or_default() += 1;
    }
    Ok(())
}
