//! Protocol-shaped leaves share JSON pairing without carrier-specific scopes.
use super::json::{LeafContext, LeafObservations, VerifiedField};
use crate::policy::{CompiledJsonPolicy, GLOBAL_JSON_ID, GlobalField, GlobalUrlFormat};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub(crate) mod jwt;
pub(crate) mod template;
pub(crate) mod url;
type Check<'a> = Box<dyn Fn(LeafContext<'_>) -> Result<LeafObservations, String> + 'a>;
pub(crate) struct ProtocolChecks<'a> {
    checks: Vec<(String, Check<'a>)>,
}
impl ProtocolChecks<'_> {
    pub(crate) fn fields(&self) -> Vec<VerifiedField<'_>> {
        self.checks
            .iter()
            .map(|(pointer, verify)| VerifiedField {
                rule_id: GLOBAL_JSON_ID,
                pointer,
                verifier: verify.as_ref(),
            })
            .collect()
    }
}
pub(crate) fn checks<'a>(
    plan: &'a CompiledJsonPolicy,
    source: &serde_json::Value,
) -> anyhow::Result<ProtocolChecks<'a>> {
    let mut checks: Vec<(String, Check<'a>)> = Vec::new();
    for (pattern, field) in &plan.fields {
        if let GlobalField::Template { formats } = field {
            for pointer in super::delivery::select(pattern, source)? {
                checks.push((
                    pointer,
                    Box::new(move |context| template::compare(context, formats)),
                ));
            }
            continue;
        }
        if let GlobalField::Jwt { signature } = field {
            for pointer in super::delivery::select(pattern, source)? {
                checks.push((
                    pointer,
                    Box::new(move |context| jwt::compare(context, plan, signature)),
                ));
            }
            continue;
        }
        let GlobalField::Url { formats } = field else {
            continue;
        };
        for pointer in super::delivery::select(pattern, source)? {
            anyhow::ensure!(
                source
                    .pointer(&pointer)
                    .is_some_and(|value| !value.is_array() && !value.is_object()),
                "URL format requires a scalar JSON leaf"
            );
            checks.push((
                pointer,
                Box::new(move |context| {
                    if context.source == context.target
                        && formats.first() != Some(&GlobalUrlFormat::Url)
                    {
                        return Ok(LeafObservations::default());
                    }
                    match formats.first() {
                        Some(GlobalUrlFormat::AwsSigv4) => aws_sigv4(context),
                        Some(GlobalUrlFormat::Url) => url::compare(context, plan),
                        None => Err("URL format unavailable".into()),
                    }
                }),
            ));
        }
    }
    Ok(ProtocolChecks { checks })
}
/// Compact JWT syntax only. Claims and signatures remain opaque token content;
/// correspondence uses the complete typed string, never a decoded field.
pub(crate) fn is_jwt(value: &serde_json::Value) -> bool {
    let Some(token) = value.as_str().filter(|token| token.len() <= 64 * 1024) else {
        return false;
    };
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .filter(|bytes| URL_SAFE_NO_PAD.encode(bytes) == part)
    };
    let Some(header) = decode(parts[0]).and_then(|bytes| crate::json_value::parse(&bytes)) else {
        return false;
    };
    let Some(claims) = decode(parts[1]).and_then(|bytes| crate::json_value::parse(&bytes)) else {
        return false;
    };
    header.is_object()
        && header
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|algorithm| !algorithm.is_empty())
        && claims.is_object()
        && decode(parts[2])
            .is_some_and(|signature| !signature.is_empty() || header["alg"] == "none")
}

/// Recognition is intentionally broader than authentication: duplicate JSON
/// members or a disallowed algorithm cannot turn a compact JWS into an exact
/// equality fallback. The authenticated parser still rejects those documents.
pub(crate) fn looks_like_jwt(value: &serde_json::Value) -> bool {
    let Some(token) = value.as_str().filter(|token| token.len() <= 64 * 1024) else {
        return false;
    };
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().take(2).all(|part| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|value| value.is_object())
    })
}

fn aws_sigv4(context: LeafContext<'_>) -> Result<LeafObservations, String> {
    let compare = || -> anyhow::Result<LeafObservations> {
        use anyhow::{Context, ensure};
        let names =
            std::collections::BTreeSet::from(["X-Amz-Date", "X-Amz-Signature", "X-Amz-Credential"]);
        let source = super::url_query::select(context.source, &names)?;
        let target = super::url_query::select(context.target, &names)?;
        ensure!(
            source.remainder == target.remainder,
            "unselected URL components differ"
        );
        let date = |query: &super::url_query::SelectedQuery| {
            super::time::parse_timestamp(
                &query.values["X-Amz-Date"],
                super::time::TimestampFormat::AmzDate,
                None,
            )
        };
        let a = date(&source)?;
        let b = date(&target)?;
        super::time::compare_timestamp_nanos(
            a,
            b,
            super::time::TimeMode::PreserveRelative,
            context.clocks.observation(),
        )?;
        let signature = |query: &super::url_query::SelectedQuery| -> anyhow::Result<()> {
            let value = query.values["X-Amz-Signature"]
                .as_str()
                .context("URL signature must be text")?;
            ensure!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "URL signature must be 64 lowercase hexadecimal characters"
            );
            Ok(())
        };
        signature(&source)?;
        signature(&target)?;
        ensure!(
            super::url_query::date_segment_remainder(
                &source.values["X-Amz-Credential"],
                '/',
                1,
                a
            )? == super::url_query::date_segment_remainder(
                &target.values["X-Amz-Credential"],
                '/',
                1,
                b
            )?,
            "URL credential scope differs"
        );
        Ok(LeafObservations {
            time_validations: 1,
            ..Default::default()
        })
    };
    compare().map_err(|error| format!("URL protocol format rejected value: {error:#}"))
}

#[cfg(test)]
mod tests;
