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
