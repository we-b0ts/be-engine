//! Published HTTP request evidence queries, separate from runtime selection.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::policy_evidence::{self, WitnessManifest};

mod observations;
#[cfg(test)]
mod tests;

const PAGE_SIZE: usize = 20;
const BODY_PAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Query {
    Failures {
        offset: usize,
    },
    Candidates {
        failure: usize,
        offset: usize,
    },
    Differences {
        failure: usize,
        candidate: usize,
        offset: usize,
    },
    Body {
        failure: usize,
        candidate: usize,
        side: Side,
        offset: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Source,
    Target,
}

pub fn query(
    report_path: &Path,
    api: &str,
    query: &Query,
    expected_report: Option<&str>,
) -> Result<Value> {
    let bytes = std::fs::read(report_path)?;
    let digest = policy_evidence::digest(&bytes);
    ensure!(
        expected_report.is_none_or(|expected| expected == digest),
        "HTTP request evidence cursor is stale; query the current issue overview again"
    );
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["finalized"] == true,
        "HTTP diagnosis requires a finalized Replay report"
    );
    let mut dataset = Dataset {
        report_path,
        report,
        manifest: None,
        private: None,
        unavailable: None,
        failures: Vec::new(),
    };
    dataset.select_failures(api)?;
    let facts = match *query {
        Query::Failures { offset } => dataset.failures(offset)?,
        Query::Candidates { failure, offset } => dataset.candidates(failure, offset)?,
        Query::Differences {
            failure,
            candidate,
            offset,
        } => dataset.differences(failure, candidate, offset)?,
        Query::Body {
            failure,
            candidate,
            side,
            offset,
        } => dataset.body(failure, candidate, side, offset)?,
    };
    Ok(json!({"report_sha256":policy_evidence::digest(&bytes),
        "session_id":dataset.report["session_id"],
        "replay_policy_fingerprint":dataset.report["replay_policy"]["fingerprint"],
        "api":api,"data":facts}))
}

struct Dataset<'a> {
    report_path: &'a Path,
    report: Value,
    manifest: Option<WitnessManifest>,
    private: Option<PathBuf>,
    unavailable: Option<&'static str>,
    // Keep physical report indices, even when this method/route selects a subset.
    failures: Vec<usize>,
}

impl Dataset<'_> {
    fn select_failures(&mut self, api: &str) -> Result<()> {
        let Some(events) = self.report["unmatched_http_requests"].as_array() else {
            return Ok(());
        };
        for (index, event) in events.iter().enumerate() {
            let Some(case_id) = event["case_id"].as_str() else {
                continue;
            };
            let dir = self.case_dir(case_id)?;
            let request: Value = serde_json::from_slice(&std::fs::read(dir.join("request.json"))?)?;
            let (method, path) = api
                .split_once(' ')
                .map_or((None, api), |(m, p)| (Some(m), p));
            let uri = request["uri"]
                .as_str()
                .context("Source request URI is missing")?;
            if method.is_none_or(|m| request["method"] == m)
                && crate::path_pattern::matches_path_pattern(
                    path,
                    &traffic_protocol_http::uri::uri_path_only(uri),
                )
            {
                self.failures.push(index);
            }
        }
        Ok(())
    }

    fn event(&self, index: usize) -> Result<&Value> {
        ensure!(
            self.failures.contains(&index),
            "HTTP failure is outside this API evidence"
        );
        self.report["unmatched_http_requests"]
            .get(index)
            .context("HTTP failure is missing")
    }

    fn case_dir(&self, id: &str) -> Result<PathBuf> {
        let dir = self.report["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["case_id"] == id)
            .and_then(|case| case["case_dir"].as_str())
            .context("HTTP failure Case directory is missing")?;
        Ok(PathBuf::from(dir))
    }

    fn open_witnesses(&mut self) -> Result<()> {
        if self.manifest.is_some() || self.unavailable.is_some() {
            return Ok(());
        }
        let Some(value) = self.report.get("policy_witnesses").filter(|v| !v.is_null()) else {
            self.unavailable = Some("historical_report_has_no_protected_request_bodies");
            return Ok(());
        };
        let manifest: WitnessManifest = serde_json::from_value(value.clone())?;
        if !manifest.complete || !manifest.sealed || manifest.omitted != 0 {
            self.unavailable = Some("protected_request_coverage_is_incomplete");
            return Ok(());
        }
        // Authentication failures are errors, never a successful empty result.
        self.private = Some(policy_evidence::verify(self.report_path, &manifest)?);
        self.manifest = Some(manifest);
        Ok(())
    }

    fn unavailable(&self) -> Value {
        json!({"presence":"unavailable","reason":self.unavailable.unwrap_or("request_body_not_retained"),
            "next_step":"Run fresh genuine Replay through the coordinator to capture independent Target request evidence."})
    }

    fn failures(&self, offset: usize) -> Result<Value> {
        ensure!(
            offset <= self.failures.len(),
            "HTTP failure page is outside the inventory"
        );
        let values = self
            .failures
            .iter()
            .skip(offset)
            .take(PAGE_SIZE)
            .map(|index| {
                let event = &self.report["unmatched_http_requests"][*index];
                json!({"failure_index":index,"case_id":event["case_id"],"scheme":event["scheme"],
                "endpoint":event["target"],"method":event["method"],"path":event["uri"],
                "reason":event["reason"],"target_observation_id":event["target_observation_id"],
                "candidates_query":Query::Candidates { failure:*index, offset:0 }})
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"total_failures":self.failures.len(),"offset":offset,"failures":values,
            "next_query":(offset.saturating_add(PAGE_SIZE)<self.failures.len())
                .then_some(Query::Failures { offset:offset.saturating_add(PAGE_SIZE) })}),
        )
    }

    fn candidates(&mut self, failure: usize, offset: usize) -> Result<Value> {
        self.event(failure)?;
        self.open_witnesses()?;
        if self.manifest.is_none() {
            return Ok(self.unavailable());
        }
        let candidates = self.observations(failure)?;
        ensure!(
            offset <= candidates.len(),
            "HTTP candidate page is outside the inventory"
        );
        let values = candidates.iter().enumerate().skip(offset).take(PAGE_SIZE).map(|(index, item)| {
            json!({"candidate_index":index,"source":item.source_identity(),
                "target_observation_id":item.target_id(),
                "association":item.association(),
                "differences_query":Query::Differences { failure, candidate:index, offset:0 },
                "source_body_query":Query::Body { failure, candidate:index, side:Side::Source, offset:0 },
                "target_body_query":Query::Body { failure, candidate:index, side:Side::Target, offset:0 }})
        }).collect::<Vec<_>>();
        Ok(
            json!({"failure_index":failure,"candidate_count":candidates.len(),"offset":offset,
            "selection":"retained runtime candidate associations; candidates are not successful matches",
            "failure_association":if self.event(failure)?["target_observation_id"].is_string() {
                "exact_target_observation" } else { "legacy_case_endpoint_method_path_candidates" },
            "ambiguous":candidates.len()>1, "candidates":values,
            "availability":if candidates.is_empty(){ self.unavailable() }else{json!({"presence":"present"})},
            "coverage":{"complete":true,"protected_observations":self.manifest.as_ref().unwrap().recorded,
                "scope":"all matching HTTP metadata; no first-256 observation limit"},
            "next_query":(offset.saturating_add(PAGE_SIZE)<candidates.len())
                .then_some(Query::Candidates { failure, offset:offset.saturating_add(PAGE_SIZE) })}),
        )
    }

    fn pair(&mut self, failure: usize, candidate: usize) -> Result<(Option<Value>, Option<Value>)> {
        self.event(failure)?;
        self.open_witnesses()?;
        if self.manifest.is_none() {
            return Ok((None, None));
        }
        let candidates = self.observations(failure)?;
        let candidate = candidates
            .get(candidate)
            .context("HTTP candidate is outside the inventory")?;
        candidate.read(self)
    }

    fn differences(&mut self, failure: usize, candidate: usize, offset: usize) -> Result<Value> {
        let (source, target) = self.pair(failure, candidate)?;
        let source_body = source.as_ref().map(body_bytes).transpose()?;
        let target_body = target.as_ref().map(body_bytes).transpose()?;
        let mut diff = match (&source_body, &target_body) {
            (Some(source), Some(target)) => {
                crate::value_contract::diagnosis::differences(source, target, offset)
            }
            _ => self.unavailable(),
        };
        if let Some(offset) = diff["next_offset"].as_u64() {
            diff["next_query"] = serde_json::to_value(Query::Differences {
                failure,
                candidate,
                offset: offset.try_into()?,
            })?;
        }
        let mut runtime = self.event(failure)?["body_comparisons"].as_array().into_iter().flatten()
            .find(|comparison| source.as_ref().is_some_and(|s| comparison["source_exchange_id"] == s["exchange_id"]))
            .cloned().unwrap_or_else(|| json!({"presence":"unavailable",
                "reason":"historical_or_native_comparison_trace_not_retained",
                "note":"Raw differences do not claim which changes remain after policy evaluation."}));
        if let (Some(source), Some(target)) = (&source_body, &target_body) {
            let observations = runtime["comparison"]["differences"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|difference| difference["pointer"].as_str())
                .map(|pointer| {
                    crate::value_contract::diagnosis::at_pointer(source, target, pointer)
                })
                .collect::<Vec<_>>();
            if !observations.is_empty() {
                runtime["original_value_observations"] = json!(observations);
            }
        }
        Ok(json!({"failure_index":failure,"candidate_index":candidate,
            "source":envelope_summary(source.as_ref(), source_body.as_deref()),
            "target":envelope_summary(target.as_ref(), target_body.as_deref()),
            "raw_body_differences":diff,"runtime_rule_comparison":runtime,
            "omitted_runtime_rule_comparisons":self.event(failure)?["omitted_body_comparisons"],
            "source_body_query":Query::Body { failure,candidate,side:Side::Source,offset:0 },
            "target_body_query":Query::Body { failure,candidate,side:Side::Target,offset:0 }}))
    }

    fn body(
        &mut self,
        failure: usize,
        candidate: usize,
        side: Side,
        offset: usize,
    ) -> Result<Value> {
        let (source, target) = self.pair(failure, candidate)?;
        let envelope = match side {
            Side::Source => source,
            Side::Target => target,
        };
        let Some(envelope) = envelope else {
            return Ok(self.unavailable());
        };
        let body = body_bytes(&envelope)?;
        ensure!(
            offset <= body.len(),
            "body offset is outside the captured body"
        );
        let mut end = offset.saturating_add(BODY_PAGE_BYTES).min(body.len());
        let (encoding, data) = if let Ok(text) = std::str::from_utf8(&body) {
            ensure!(
                text.is_char_boundary(offset),
                "body offset is not a UTF-8 boundary"
            );
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            ("utf8", text[offset..end].to_owned())
        } else {
            ("base64", STANDARD.encode(&body[offset..end]))
        };
        Ok(
            json!({"side":side,"presence":"present","original_len":body.len(),
            "sha256":policy_evidence::digest(&body),"capture_truncated":false,
            "offset":offset,"returned_bytes":end-offset,"encoding":encoding,"data":data,
            "page_truncated":end<body.len(),"end_of_body":end==body.len(),
            "next_query":(end<body.len()).then_some(Query::Body { failure,candidate,side,offset:end })}),
        )
    }
}

fn body_bytes(envelope: &Value) -> Result<Vec<u8>> {
    super::contracts::witness_value(
        &serde_json::to_vec(envelope)?,
        crate::policy::Surface::DependencyRequest,
    )?
    .context("HTTP request body is unavailable")
}

fn envelope_summary(envelope: Option<&Value>, body: Option<&[u8]>) -> Value {
    let Some(envelope) = envelope else {
        return json!({"presence":"unavailable"});
    };
    json!({"presence":"present","exchange_id":envelope["exchange_id"],"scheme":envelope["scheme"],
        "endpoint":envelope["endpoint"],"method":envelope["method"],
        "path":envelope["uri"].as_str().map(traffic_protocol_http::uri::uri_path_only),
        "request_started_at":envelope["request_started_at"],
        "content_type":envelope["request_headers"]["content-type"],
        "content_encoding":envelope["request_headers"]["content-encoding"],
        "body":{"original_len":body.map(<[u8]>::len),"sha256":body.map(policy_evidence::digest),"capture_truncated":false}})
}

pub fn source_summary(event: &Value) -> Result<Option<Value>> {
    if event["event_type"] != "http_exchange" {
        return Ok(None);
    }
    let record: traffic_protocol_http::recorded::RecordedExchange =
        serde_json::from_value(event.clone())?;
    let (scheme, endpoint) = record.identity()?;
    Ok(Some(json!({"host":endpoint.host,"port":endpoint.port,
        "scheme":scheme,"method":record.method,"path":traffic_protocol_http::uri::uri_path_only(&record.uri),
        "exchange_id":record.id,"body_capture_truncated":record.request_body.truncated,
        "body_original_len":event["request_body"]["original_len"],
        "body_encoding":record.request_body.encoding})))
}
