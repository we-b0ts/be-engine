//! Native URI parsing, query normalization and physical parameter observations.
use hyper::Uri;

pub fn normalize_uri(value: &str) -> (String, Vec<(String, String)>) {
    let parsed = value.parse::<Uri>().ok();
    let path = parsed
        .as_ref()
        .map(|uri| uri.path())
        .unwrap_or_else(|| value.split('?').next().unwrap_or(value));
    let raw_query = parsed
        .as_ref()
        .and_then(Uri::query)
        .or_else(|| value.split_once('?').map(|(_, query)| query))
        .unwrap_or_default();
    let mut query = form_urlencoded::parse(raw_query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    query.sort();
    (path.to_string(), query)
}

pub fn uri_path_only(value: &str) -> String {
    value
        .parse::<Uri>()
        .ok()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| value.split('?').next().unwrap_or(value).to_string())
}

pub fn count_query_parameters(uri: &str, key_matches: impl Fn(&str) -> bool) -> usize {
    let parsed = uri.parse::<Uri>().ok();
    let query = parsed
        .as_ref()
        .and_then(Uri::query)
        .or_else(|| uri.split_once('?').map(|(_, query)| query))
        .unwrap_or_default();
    form_urlencoded::parse(query.as_bytes())
        .filter(|(part_key, _)| key_matches(part_key))
        .count()
}

use anyhow::{Context, Result, ensure};
use std::str::FromStr as _;

pub fn target_uri(origin: &str, recorded_uri: &str) -> Result<Uri> {
    let origin = Uri::from_str(origin).context("invalid HTTP request origin")?;
    let recorded = Uri::from_str(recorded_uri).context("invalid recorded request URI")?;
    let path_and_query = recorded
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    ensure!(
        path_and_query.starts_with('/'),
        "recorded request URI must have an absolute path"
    );
    Uri::builder()
        .scheme(
            origin
                .scheme()
                .context("HTTP request origin has no scheme")?
                .clone(),
        )
        .authority(
            origin
                .authority()
                .context("HTTP request origin has no authority")?
                .clone(),
        )
        .path_and_query(path_and_query)
        .build()
        .context("failed to build recorded request URI")
}
