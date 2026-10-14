//! Explicit HTTP JSON timestamps, compared against dependency-local clocks.
use super::*;
use crate::replay::{assertion::RequestTimes, policy::config::HttpSelector};
#[cfg(test)]
mod tests;

pub(super) fn validate(http: &HttpSelector) -> Result<()> {
    ensure!(
        !http.json.time.is_empty() && http.json.time.len() <= 32,
        "HTTP JSON time contracts require 1..32 fields"
    );
    ensure!(
        http.json.unordered.is_empty() && http.query.is_empty() && http.headers.is_empty(),
        "HTTP JSON time contracts keep other request matching exact"
    );
    for (pointer, field) in &http.json.time {
        super::super::response::validate_json_pointer(pointer)?;
        ensure!(
            !pointer.is_empty() && !pointer.split('/').any(|part| part == "*"),
            "HTTP JSON time fields require exact non-root pointers"
        );
        ensure!(
            http.json.time.keys().all(|other| pointer == other
                || !super::super::response_locations_overlap(pointer, other)),
            "HTTP JSON time fields overlap"
        );
        config::tolerance(&field.tolerance)?;
    }
    Ok(())
}

pub(super) fn compare(
    http: &HttpSelector,
    source: &[u8],
    actual: &[u8],
    clocks: RequestTimes,
) -> Result<usize> {
    let mut source = crate::replay::json_order::parse(source)
        .context("source request requires bounded complete unique-member JSON")?;
    let mut actual = crate::replay::json_order::parse(actual)
        .context("target request requires bounded complete unique-member JSON")?;
    let mut times = Vec::new();
    for (pointer, field) in &http.json.time {
        let a = source
            .pointer_mut(pointer)
            .context("source time field is missing")?;
        let b = actual
            .pointer_mut(pointer)
            .context("target time field is missing")?;
        times.push(super::time::compare(a, b, field, clocks)?);
        *a = Value::Null;
        *b = Value::Null;
    }
    if let Some(first) = times.first() {
        ensure!(
            times
                .iter()
                .all(|pair| ((pair.1 - first.1) - (pair.0 - first.0)).abs() <= 0.000_001),
            "HTTP JSON time parameter relationship changed"
        );
    }
    ensure!(source == actual, "unselected HTTP JSON fields differ");
    Ok(times.len())
}

impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn preview_http_json_time(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        source_uri: &str,
        actual_uri: &str,
        source: &[u8],
        source_headers: &BTreeMap<String, Vec<String>>,
        actual: &[u8],
        headers: &BTreeMap<String, Vec<String>>,
        clocks: RequestTimes,
    ) -> Option<Result<Decision>> {
        let rules: Vec<_> = self
            .selected(case, target, DependencyProtocol::Http)
            .into_iter()
            .filter(|rule| {
                rule.http.as_ref().is_some_and(|h| {
                    !h.json.time.is_empty()
                        && h.method == method
                        && super::super::pattern::path_pattern_matches(
                            &h.path,
                            &super::super::pattern::uri_path(source_uri),
                        )
                })
            })
            .collect();
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            ensure!(rules.len() == 1, "overlapping HTTP JSON time contracts");
            ensure!(
                crate::replay::http::uri_mismatch_reason(source_uri, actual_uri, &[]).is_none(),
                "HTTP JSON time contracts require exact path and query"
            );
            ensure!(
                crate::replay::http::request_headers::exact_contract_match(source_headers, headers),
                "HTTP JSON time identity headers differ"
            );
            let rule = rules[0];
            let validations = compare(rule.http.as_ref().unwrap(), source, actual, clocks)?;
            Ok(Decision {
                ids: vec![rule.id.clone()],
                time_validations: validations,
                ..Default::default()
            })
        })())
    }
}
