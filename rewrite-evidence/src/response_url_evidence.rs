//! Source response evidence for a caller-reported unrecorded IP.
use std::collections::BTreeSet;
use std::path::Path;

use crate::http::rewrite::{UrlTarget, inspect_url_target};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use super::{case_dependencies, evidence, fingerprint, model::RewriteState};

const MAX_CANDIDATES: usize = 16;

pub fn facts(target_root: &Path, state: &RewriteState) -> Result<Value> {
    let reported = state
        .active_issue
        .as_ref()
        .and_then(|issue| issue.recorder_capture_diagnosis.as_ref())
        .context("report the IP source through route --cause unrecorded-ip first")?;
    let endpoint: std::net::SocketAddr = reported["endpoint"]
        .as_str()
        .context("IP endpoint missing")?
        .parse()?;
    let case_id = reported["case_id"]
        .as_str()
        .context("reported case missing")?;
    let root = evidence::case_source(target_root, state)?;
    let case_dir = crate::case_group::resolve_published_case_dir(&root, case_id)?;
    let request: Value = serde_json::from_slice(&std::fs::read(case_dir.join("request.json"))?)?;
    let api: crate::RecordingApi = state.api.parse()?;
    ensure!(
        api.matches(
            &request["method"]
                .as_str()
                .context("case request method missing")?
                .parse()?,
            &request["uri"]
                .as_str()
                .context("case request URI missing")?
                .parse()?
        ),
        "reported case belongs to another API"
    );
    let endpoints = BTreeSet::from([(endpoint.ip().to_string(), endpoint.port())]);
    let mut candidates = Vec::new();
    let mut errors = Vec::new();
    for path in [
        case_dir.join("dependencies.jsonl"),
        root.join("global-dependencies.jsonl"),
    ] {
        if crate::dependency_index::scoped::exists(&path)
            && scan(&path, case_id, &endpoints, &mut candidates).is_err()
        {
            errors.push("recorded JSON response scan unavailable or exceeds bounds; inspect case dependencies");
        }
    }
    candidates.sort_by_key(|candidate| candidate.to_string());
    candidates.dedup();
    let app = crate::AppConfig::load(target_root.join(".traffic-e2e/project.yaml"))?;
    for candidate in &mut candidates {
        let method = candidate["method"]
            .as_str()
            .context("candidate method missing")?
            .parse()?;
        let uri = candidate["path"]
            .as_str()
            .context("candidate path missing")?
            .parse()?;
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            candidate["content_type"]
                .as_str()
                .context("candidate content type missing")?
                .parse()?,
        );
        let input = crate::http::rewrite::RewriteInput {
            method: &method,
            uri: &uri,
            authority: candidate["authority"].as_str(),
            status: hyper::StatusCode::from_u16(
                candidate["status"]
                    .as_u64()
                    .context("candidate status missing")? as u16,
            )?,
            headers: &headers,
            body: &[],
        };
        let matching = app
            .http_response_rewrite
            .rules
            .iter()
            .filter(|rule| {
                app.http_response_rewrite.is_enabled()
                    && crate::http::rewrite::matches(rule, &input)
            })
            .collect::<Vec<_>>();
        let configured = if matching.first().is_some_and(|rule| rule.plugin.is_none()) {
            matching
                .into_iter()
                .filter(|rule| {
                    rule.plugin.is_none()
                        && rule
                            .pointers
                            .iter()
                            .any(|pointer| candidate["pointer"] == *pointer)
                })
                .map(|rule| rule.name.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        candidate["configured_rules"] = json!(configured);
    }
    Ok(json!({
        "reported": reported,
        "http_response_url_candidates": candidates,
        "http_response_url_scan": {"max_candidates":MAX_CANDIDATES, "bounded":true, "errors":errors},
        "rewrite_enabled":app.http_response_rewrite.enabled,
        "does_not_prove":"Reported omission and source consumption are caller evidence. A matching JSON URL does not prove a firewall rejection, causality, or that an equivalent dependency is absent."
    }))
}

fn scan(
    path: &Path,
    case_id: &str,
    endpoints: &BTreeSet<(String, u16)>,
    candidates: &mut Vec<Value>,
) -> Result<()> {
    ensure!(
        std::fs::metadata(path)?.len() <= 64 * 1024 * 1024,
        "dependency scan exceeds 64 MiB"
    );
    case_dependencies::read_events(path, |event| {
        if candidates.len() >= MAX_CANDIDATES || event["event_type"] != "http_exchange" {
            return Ok(());
        }
        let Some(status) = event["response_status"].as_u64() else {
            return Ok(());
        };
        if !(200..300).contains(&status) || event["response_body"]["truncated"] != false {
            return Ok(());
        }
        let content_type = header(event, "content-type")
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if content_type != "application/json" && !content_type.ends_with("+json") {
            return Ok(());
        }
        let Some(authority) = event["authority"].as_str().filter(|text| text.len() <= 256) else {
            return Ok(());
        };
        let Some(method) = event["method"].as_str() else {
            return Ok(());
        };
        let Some(uri) = event["uri"]
            .as_str()
            .and_then(|value| value.parse::<hyper::Uri>().ok())
        else {
            return Ok(());
        };
        let path = uri.path();
        if path.len() > 1024 || method.len() > 16 {
            return Ok(());
        }
        let Some(response_id) = event["id"].as_str() else {
            return Ok(());
        };
        if event["response_body"]["encoding"] != "base64" {
            return Ok(());
        }
        let body = STANDARD.decode(
            event["response_body"]["data"]
                .as_str()
                .context("HTTP response body missing")?,
        )?;
        let encoding = header(event, "content-encoding").unwrap_or("identity");
        let decoded = crate::http::content_encoding::decode(
            &body,
            &encoding.to_ascii_lowercase(),
            1024 * 1024,
        )?;
        if decoded.truncated || decoded.body.len() > 1024 * 1024 {
            return Ok(());
        }
        let Ok(document) = serde_json::from_slice::<Value>(&decoded.body) else {
            return Ok(());
        };
        let mut leaves = Vec::new();
        let mut remaining = 4096;
        url_leaves(&document, "", 0, &mut remaining, &mut leaves);
        for (pointer, target) in leaves {
            let ip = target.ip;
            let port = target.port;
            if !endpoints.contains(&(ip.to_string(), port)) {
                continue;
            }
            if candidates.len() >= MAX_CANDIDATES {
                break;
            }
            candidates.push(json!({
                "case_id":case_id,"response_id":response_id,
                "response_digest":fingerprint::id(&[&event.to_string()]),
                "authority":authority,"method":method,"path":path,"pointer":pointer,
                "status":status,"content_type":content_type,
                "destination":{"host":ip.to_string(),"port":port},"scheme":target.scheme,
                "preview_host":target.alias,
                "evidence_kind":"recorded_response", "source_consumption_proven":false
            }));
        }
        Ok(())
    })
}

fn header<'a>(event: &'a Value, name: &str) -> Option<&'a str> {
    event["response_headers"]
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))?
        .1
        .as_array()?
        .first()?
        .as_str()
}

fn url_leaves(
    value: &Value,
    pointer: &str,
    depth: usize,
    remaining: &mut usize,
    leaves: &mut Vec<(String, UrlTarget)>,
) {
    if depth > 24 || *remaining == 0 || pointer.len() > 512 {
        return;
    }
    *remaining -= 1;
    match value {
        Value::String(text) if text.len() <= 8192 => {
            if let Ok(Some(target)) = inspect_url_target(text) {
                leaves.push((pointer.to_string(), target));
            }
        }
        Value::Object(fields) => {
            for (field, value) in fields.iter().take(*remaining) {
                url_leaves(
                    value,
                    &format!("{pointer}/{}", field.replace('~', "~0").replace('/', "~1")),
                    depth + 1,
                    remaining,
                    leaves,
                );
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate().take(*remaining) {
                url_leaves(
                    value,
                    &format!("{pointer}/{index}"),
                    depth + 1,
                    remaining,
                    leaves,
                );
            }
        }
        _ => {}
    }
}
