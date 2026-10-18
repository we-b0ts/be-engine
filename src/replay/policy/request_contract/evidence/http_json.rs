//! Protected JSON body witnesses retain the target dependency clock for planning.
use super::*;
use crate::replay::assertion::RequestTimes;

#[derive(Serialize, Deserialize)]
struct JsonWitness {
    source_uri: String,
    uri: String,
    body: Vec<u8>,
    headers: BTreeMap<String, Vec<String>>,
    request_started_at: DateTime<Utc>,
}
impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_http_json(
        &self,
        case: &str,
        target: &TargetKey,
        method: &str,
        path: &str,
        source: &[u8],
        source_headers: &BTreeMap<String, Vec<String>>,
        actual: &[u8],
        headers: &BTreeMap<String, Vec<String>>,
        clocks: RequestTimes,
        actual_uri: &str,
    ) {
        let (Some(_), Some(request_started_at)) = (clocks.source, clocks.target) else {
            return;
        };
        if crate::replay::json_order::parse(source).is_none()
            || crate::replay::json_order::parse(actual).is_none()
            || !crate::replay::http::request_headers::exact_contract_match(source_headers, headers)
            || crate::replay::http::uri_mismatch_reason(path, actual_uri, &[]).is_some()
        {
            return;
        }
        let actual = serde_json::to_vec(&JsonWitness {
            source_uri: path.into(),
            uri: actual_uri.into(),
            body: actual.to_vec(),
            headers: headers.clone(),
            request_started_at,
        })
        .expect("HTTP JSON witness serialization");
        self.observe(
            case,
            target,
            method,
            0,
            &super::super::super::pattern::uri_path(path),
            "http_json_request_time",
            source,
            &actual,
            clocks.target,
        );
    }
}

pub(super) fn verify(
    rule: &ReplayDependencyRule,
    candidate: &Candidate,
    event: &Value,
    source: &[u8],
    actual: &[u8],
    dir: &Path,
) -> Result<bool> {
    let http = rule.http.as_ref().context("missing HTTP selector")?;
    if http.json.time.is_empty()
        || http.method != candidate.command
        || !super::super::super::pattern::path_pattern_matches(
            &http.path,
            &super::super::super::pattern::uri_path(&candidate.path),
        )
    {
        return Ok(false);
    }
    let actual: JsonWitness = serde_json::from_slice(actual)?;
    if event["uri"] != actual.source_uri {
        return Ok(false);
    }
    ensure!(
        crate::replay::http::uri_mismatch_reason(&actual.source_uri, &actual.uri, &[]).is_none(),
        "HTTP JSON witness path or query differs"
    );
    let mut headers = serde_json::from_value(event["request_headers"].clone())?;
    crate::request_headers::decrypt_dependency_headers(
        &mut headers,
        &dir.join("dependencies.jsonl"),
    )?;
    ensure!(
        crate::replay::http::request_headers::exact_contract_match(&headers, &actual.headers),
        "HTTP JSON witness identity headers differ"
    );
    let comparison = super::super::http_json::TimeComparison::new(http, source, &actual.body)?;
    // Discovery retains all same-endpoint pairs before the time fields are known.
    // Different stable bodies belong to different requests, not an invalid rule.
    if !comparison.stable_fields_match() {
        return Ok(false);
    }
    let record = serde_json::from_value(event.clone())?;
    let clocks = RequestTimes {
        source: crate::replay::http::request_headers::time_reference::source(&record),
        target: Some(actual.request_started_at),
    };
    comparison.validate_times(clocks)?;
    Ok(true)
}
