//! Post-failure candidate discovery. It never serves an unconfigured request.
use super::*;
use serde_json::json;
use std::fs;

#[derive(Deserialize)]
struct Report {
    #[serde(default)]
    finalized: bool,
    #[serde(default)]
    unmatched_http_requests: Vec<Unmatched>,
}

#[derive(Deserialize)]
struct Unmatched {
    case_id: Option<String>,
    scheme: HttpReplayScheme,
    target: TargetKey,
    method: String,
    uri: String,
    #[serde(default)]
    request_fingerprint: Option<String>,
}

pub(crate) fn discover(source: &Path, report_path: &Path, use_cache: bool) -> Result<Value> {
    discover_selected(source, report_path, use_cache, None)
}

fn discover_selected(
    source: &Path,
    report_path: &Path,
    use_cache: bool,
    selector: Option<&HttpCrossCaseSelector>,
) -> Result<Value> {
    let bytes = fs::read(report_path)?;
    let report: Report = serde_json::from_slice(&bytes)?;
    if !report.finalized {
        return Ok(json!({"candidates": [], "unavailable": "Replay report is not finalized"}));
    }
    let unmatched: Vec<_> = report
        .unmatched_http_requests
        .iter()
        .filter(|r| r.case_id.is_some())
        .filter(|r| {
            selector.is_none_or(|s| {
                r.request_fingerprint.is_some()
                    && r.target.host == super::super::super::normalize_host(&s.host)
                    && r.target.port == s.port
                    && r.method.eq_ignore_ascii_case(&s.method)
                    && uri_path_only(&r.uri) == s.path
            })
        })
        .collect();
    if unmatched.is_empty() {
        return Ok(json!({"candidates": [], "omitted_candidates": 0}));
    }
    let (root, files) = match recording::files(source) {
        Ok(value) => value,
        Err(_) => {
            return Ok(
                json!({"candidates": [], "unavailable": "no complete standard recording boundary"}),
            );
        }
    };
    // Invalidate derived lookup when either replay evidence or any source file identity changes.
    let mut hash = Sha256::new();
    hash.update(&bytes);
    for file in &files {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(file)?;
        hash.update(file.as_os_str().as_encoded_bytes());
        hash.update(format!(
            "{}:{}:{}:{}:{}:{}",
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec()
        ));
    }
    let revision = format!("{:x}", hash.finalize());
    let cache = report_path.with_extension("http-cross-case.json");
    if use_cache
        && let Ok(bytes) = fs::read(&cache)
        && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        && value["evidence_revision"] == revision
    {
        return Ok(value);
    }
    let mut candidates = Vec::new();
    let mut total = 0usize;
    for file in &files {
        let origin = recording::case_id(file)?;
        recording::visit(file, |line, record| {
            let identity = identity_from_record(&record)?;
            let relevant: Vec<_> = unmatched
                .iter()
                .filter(|r| {
                    r.case_id.as_deref() != Some(origin.as_str())
                        && r.scheme == identity.scheme
                        && r.target == identity.target
                        && r.method.eq_ignore_ascii_case(&record.method)
                        && uri_path_only(&r.uri) == uri_path_only(&record.uri)
                })
                .collect();
            if relevant.is_empty() || require_replayable(&record).is_err() {
                return Ok(());
            }
            let fingerprint = recorded_fingerprint(&record)?;
            for request in relevant {
                if request
                    .request_fingerprint
                    .as_ref()
                    .is_some_and(|actual| actual != &fingerprint)
                {
                    continue;
                }
                total += 1;
                if candidates.len() >= 64 {
                    continue;
                }
                let case_dir = file.parent().context("missing case directory")?;
                let api = case_dir.join("request.json");
                let api: Option<Value> = fs::read(api)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok());
                let api_path = api
                    .as_ref()
                    .and_then(|a| a.get("api_pattern").or_else(|| a.get("uri")))
                    .and_then(Value::as_str)
                    .map(uri_path_only);
                candidates.push(json!({
                    "consumer_case_id": request.case_id,
                    "origin_case_id": origin,
                    "origin_api_path": api_path,
                    "selector": {"host": identity.target.host, "port": identity.target.port,
                        "method": record.method, "path": uri_path_only(&record.uri)},
                    "scheme": identity.scheme,
                    "response_status": record.response_status,
                    "request_match": if request.request_fingerprint.is_some() { "verified" } else { "unavailable" },
                    "record": {"path": file.strip_prefix(&root).unwrap_or(file), "line": line},
                }));
            }
            Ok(())
        })?;
    }
    let value = json!({"evidence_revision": revision, "candidates": candidates,
        "omitted_candidates": total.saturating_sub(64),
        "does_not_prove": "matching requests do not prove shared cache semantics; inspect source initialization, refresh and side effects"});
    if use_cache {
        // This is disposable derived evidence, never a mutation of a recording.
        let _ = crate::config::edit::write_atomic(&cache, &serde_json::to_vec(&value)?);
    }
    Ok(value)
}

pub(crate) fn verify_candidate(
    source: &Path,
    report: &Path,
    selector: &HttpCrossCaseSelector,
) -> Result<Value> {
    selector.validate()?;
    let evidence = discover_selected(source, report, false, Some(selector))?;
    ensure!(
        evidence["candidates"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| {
                item["request_match"] == "verified"
                    && serde_json::from_value::<HttpCrossCaseSelector>(item["selector"].clone())
                        .is_ok_and(|candidate| candidate == *selector)
            })),
        "no verified cross-case candidate for this selector; rerun replay if request identity evidence is unavailable"
    );
    // Validate all exchanges authorized by the selector, including ones outside the bounded preview.
    let (_, files) = recording::files(source)?;
    for file in files {
        recording::visit(&file, |_, record| {
            if selector.matches(&record) {
                require_replayable(&record)?;
            }
            Ok(())
        })?;
    }
    Ok(evidence)
}
