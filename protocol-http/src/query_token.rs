//! Bounded URL query extraction that retains every unselected raw byte.
use anyhow::{Context, Result, ensure};

const MAX_URL_BYTES: usize = 128 * 1024;

pub fn validate_parameter(parameter: &str) -> Result<()> {
    ensure!(
        !parameter.is_empty()
            && parameter.len() <= 128
            && parameter
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)),
        "JWT URL query selector requires an unreserved ASCII name"
    );
    Ok(())
}

pub struct QueryToken<'a> {
    pub token: String,
    pub prefix: &'a str,
    pub suffix: &'a str,
}

fn validate(raw: &str) -> Result<()> {
    ensure!(
        raw.len() <= MAX_URL_BYTES
            && !raw
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
        "invalid JWT URL"
    );
    let parsed = if raw.starts_with('/') && !raw.starts_with("//") {
        url::Url::parse("https://jwt-response.invalid")?.join(raw)?
    } else {
        url::Url::parse(raw)?
    };
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "JWT URL requires HTTP(S)"
    );
    let bytes = raw.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%' {
            ensure!(
                bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit),
                "invalid JWT URL percent encoding"
            );
        }
    }
    Ok(())
}

pub fn select<'a>(raw: &'a str, parameter: &str) -> Result<QueryToken<'a>> {
    validate(raw)?;
    // A '?' in a fragment never starts a query.
    let head = raw.split('#').next().unwrap_or(raw);
    let (range, token) =
        query_token_range(head, parameter)?.context("JWT URL query parameter is absent")?;
    ensure!(!token.is_empty(), "JWT URL query parameter is empty");
    Ok(QueryToken {
        token,
        prefix: &raw[..range.start],
        suffix: &raw[range.end..],
    })
}

/// Format-only discovery. No signature, generation, or rule eligibility is proven.
pub fn has_candidate_matching(raw: &str, candidate: impl Fn(&str) -> bool) -> bool {
    if validate(raw).is_err() {
        return false;
    }
    raw.split('#')
        .next()
        .and_then(|head| head.split_once('?'))
        .is_some_and(|(_, query)| {
            url::form_urlencoded::parse(query.as_bytes())
                .take(64)
                .any(|(_, value)| candidate(&value))
        })
}

pub fn query_token_range(
    uri: &str,
    wanted: &str,
) -> Result<Option<(std::ops::Range<usize>, String)>> {
    let Some(question) = uri.find('?') else {
        return Ok(None);
    };
    let query_start = question + 1;
    let query_end = uri[query_start..]
        .find('#')
        .map(|offset| query_start + offset)
        .unwrap_or(uri.len());
    let query = &uri[query_start..query_end];
    let mut selected = None;
    let mut offset = query_start;
    for component in query.split('&') {
        let (raw_name, raw_value) = component.split_once('=').unwrap_or((component, ""));
        let decoded_name = url::form_urlencoded::parse(component.as_bytes())
            .next()
            .map(|(name, _)| name.into_owned())
            .unwrap_or_default();
        if decoded_name == wanted {
            ensure!(selected.is_none(), "ambiguous JWT query parameter values");
            let value_start = offset + raw_name.len() + usize::from(component.contains('='));
            let value_end = value_start + raw_value.len();
            let decoded_value = url::form_urlencoded::parse(component.as_bytes())
                .next()
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default();
            selected = Some((value_start..value_end, decoded_value));
        }
        offset += component.len() + 1;
    }
    Ok(selected)
}
