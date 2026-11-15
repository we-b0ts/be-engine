use std::collections::BTreeMap;

use hyper::Uri;
use url::form_urlencoded;

pub fn uri_path(value: &str) -> String {
    value
        .parse::<Uri>()
        .ok()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| value.split('?').next().unwrap_or(value).to_string())
}

pub fn query_values(uri: &str) -> BTreeMap<String, Vec<String>> {
    let parsed = uri.parse::<Uri>().ok();
    let query = parsed
        .as_ref()
        .and_then(Uri::query)
        .or_else(|| uri.split_once('?').map(|(_, query)| query))
        .unwrap_or_default();
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        values
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    values
}

pub fn path_pattern_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let value = value.split('/').collect::<Vec<_>>();
    path_segments_match(&pattern, &value)
}

fn path_segments_match(pattern: &[&str], value: &[&str]) -> bool {
    match (pattern.split_first(), value.split_first()) {
        (None, None) => true,
        (Some((&"**", remaining)), _) => {
            path_segments_match(remaining, value)
                || (!value.is_empty() && path_segments_match(pattern, &value[1..]))
        }
        (Some((part, remaining_pattern)), Some((value, remaining_value))) => {
            text_pattern_matches(part, value)
                && path_segments_match(remaining_pattern, remaining_value)
        }
        _ => false,
    }
}

pub fn text_pattern_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut matches = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    matches[0][0] = true;
    for index in 1..=pattern.len() {
        if pattern[index - 1] == b'*' {
            matches[index][0] = matches[index - 1][0];
        }
        for value_index in 1..=value.len() {
            matches[index][value_index] = match pattern[index - 1] {
                b'*' => matches[index - 1][value_index] || matches[index][value_index - 1],
                b'?' => matches[index - 1][value_index - 1],
                byte => byte == value[value_index - 1] && matches[index - 1][value_index - 1],
            };
        }
    }
    matches[pattern.len()][value.len()]
}
