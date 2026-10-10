//! Bounded URL query extraction that retains every unselected raw byte.
use anyhow::{Context, Result, ensure};

const MAX_URL_BYTES: usize = 128 * 1024;

pub(crate) struct QueryToken<'a> {
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

pub(crate) fn select<'a>(raw: &'a str, parameter: &str) -> Result<QueryToken<'a>> {
    validate(raw)?;
    // A '?' in a fragment never starts a query.
    let head = raw.split('#').next().unwrap_or(raw);
    let (range, token) =
        super::query_token_range(head, parameter)?.context("JWT URL query parameter is absent")?;
    ensure!(!token.is_empty(), "JWT URL query parameter is empty");
    Ok(QueryToken {
        token,
        prefix: &raw[..range.start],
        suffix: &raw[range.end..],
    })
}

/// Format-only discovery. No signature, generation, or rule eligibility is proven.
pub(crate) fn has_candidate(raw: &str) -> bool {
    if validate(raw).is_err() {
        return false;
    }
    raw.split('#')
        .next()
        .and_then(|head| head.split_once('?'))
        .is_some_and(|(_, query)| {
            url::form_urlencoded::parse(query.as_bytes())
                .take(64)
                .any(|(_, value)| super::Token::parse(&value).ok().flatten().is_some())
        })
}
