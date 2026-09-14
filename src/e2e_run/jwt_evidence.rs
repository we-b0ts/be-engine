//! Bounded JWT time observations from the exact finalized failed HTTP attempt.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{E2eRunContext, evidence::finalized_focused_evidence};
use crate::request_rules::{
    JwtTokenLocation,
    jwt::{self, Algorithm, Token},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JwtTimeCase {
    pub case_id: String,
    #[serde(flatten)]
    pub location: JwtTokenLocation,
    pub algorithm: Algorithm,
    pub source_status: u64,
    pub target_status: u64,
    pub recorded_at: DateTime<Utc>,
    pub replayed_at: DateTime<Utc>,
    pub replay_time_source: String,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub request_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JwtTimeEvidence {
    pub attempt: u64,
    pub candidates: Vec<JwtTimeCase>,
    pub omitted_candidates: usize,
    pub signature_verified: bool,
}

pub(crate) fn query(context: E2eRunContext, api: &str) -> Result<JwtTimeEvidence> {
    let (state, _) = finalized_focused_evidence(context, api)?;
    let mut candidates = Vec::new();
    for case in &state.cases {
        let Some(assertion) = &case.response_assertion else {
            continue;
        };
        let actual: Value = serde_json::from_slice(&std::fs::read(&assertion.actual_response)?)?;
        let expected: Value =
            serde_json::from_slice(&std::fs::read(&assertion.expected_response)?)?;
        if actual["status"] != 401 || expected["status"] == 401 {
            continue;
        }
        // Already transformed input cannot be diagnosed from the original token's exp.
        if actual["request_rules"].as_array().is_some_and(|rules| {
            rules
                .iter()
                .any(|r| r["outcome"] == "time_shifted_signature_verified")
        }) {
            continue;
        }
        let Some(source_status) = expected["status"].as_u64() else {
            continue;
        };
        let (replayed_at, time_source) = replay_time(
            &actual,
            &state.replay_report,
            &case.case_id,
            state.started_at,
        )?;
        let request_path = case.case_dir.join("request.json");
        let raw = crate::request_headers::load_request_file(&request_path)?;
        let request: Value = serde_json::from_slice(&raw)?;
        let header_locations = request["headers"]
            .as_object()
            .into_iter()
            .flat_map(|headers| headers.keys())
            .map(|header| JwtTokenLocation::BearerHeader {
                header: header.to_ascii_lowercase(),
            });
        let query_locations = request["uri"]
            .as_str()
            .and_then(|uri| uri.split_once('?').map(|(_, query)| query))
            .map(|query| query.split('#').next().unwrap_or_default())
            .into_iter()
            .flat_map(|query| query.split('&'))
            .filter_map(|component| {
                url::form_urlencoded::parse(component.as_bytes())
                    .next()
                    .map(|(name, _)| name.into_owned())
            })
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 128
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                    })
            })
            .map(|query_param| JwtTokenLocation::QueryParameter { query_param });
        for location in header_locations.chain(query_locations) {
            let Some(token) = jwt::request_token(&request, &location)? else {
                continue;
            };
            let Some(token) = Token::parse(&token)? else {
                continue;
            };
            let Ok(Some(exp)) = token.integer_claim("exp") else {
                continue;
            };
            let (Ok(nbf), Ok(iat)) = (token.integer_claim("nbf"), token.integer_claim("iat"))
            else {
                continue;
            };
            let recorded_at = jwt::request_timestamp(&request)?;
            if recorded_at.timestamp() >= exp
                || replayed_at.timestamp() <= exp
                || nbf.is_some_and(|v| v > recorded_at.timestamp())
            {
                continue;
            }
            candidates.push(JwtTimeCase {
                case_id: case.case_id.clone(),
                location,
                algorithm: token.algorithm,
                source_status,
                target_status: 401,
                recorded_at,
                replayed_at,
                replay_time_source: time_source.clone(),
                exp,
                nbf,
                iat,
                request_fingerprint: digest(&std::fs::read(&request_path)?),
            });
        }
    }
    let omitted_candidates = candidates.len().saturating_sub(20);
    candidates.truncate(20);
    Ok(JwtTimeEvidence {
        attempt: state.sequence,
        candidates,
        omitted_candidates,
        signature_verified: false,
    })
}

fn replay_time(
    actual: &Value,
    report: &std::path::Path,
    case_id: &str,
    started: DateTime<Utc>,
) -> Result<(DateTime<Utc>, String)> {
    if let Some(time) = actual["request_sent_at"].as_str() {
        return Ok((
            time.parse().context("invalid request send timestamp")?,
            "request_sent_at".into(),
        ));
    }
    // Legacy reports retain a before-send case-begin observation. It is a
    // conservative lower bound, not a fabricated exact send time.
    if report.is_file() {
        let report: Value = serde_json::from_slice(&std::fs::read(report)?)?;
        if let Some(time) = report["egress_rejections"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|v| v["case_id"] == case_id)
            .and_then(|v| v["observed_from"].as_str())
        {
            return Ok((time.parse()?, "case_begin_lower_bound".into()));
        }
    }
    Ok((started, "attempt_start_lower_bound".into()))
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn verify_candidate(
    case: &JwtTimeCase,
    request: &Value,
    key: &[u8],
    leeway_seconds: i64,
) -> Result<()> {
    ensure!(leeway_seconds >= 0, "JWT leeway must be nonnegative");
    ensure!(
        case.replayed_at.timestamp().saturating_sub(case.exp) > leeway_seconds,
        "JWT was not expired beyond the configured validation leeway at replay"
    );
    let raw =
        jwt::request_token(request, &case.location)?.context("JWT evidence token is absent")?;
    let token = Token::parse(&raw)?.context("JWT evidence is not a supported HMAC JWT")?;
    ensure!(
        token.algorithm == case.algorithm && token.verify(key),
        "JWT signing key does not verify the original evidence token"
    );
    ensure!(
        token.integer_claim("exp")? == Some(case.exp)
            && jwt::request_timestamp(request)? == case.recorded_at,
        "JWT evidence request changed"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support;
