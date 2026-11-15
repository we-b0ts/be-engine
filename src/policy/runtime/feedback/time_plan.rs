//! Preflight response time rules against the same captured clocks used by Replay.
use super::*;
use crate::{
    primary_protocol::assertion::ResponseGatewayProtocol,
    primary_protocol::assertion::read_actual_response_body,
    primary_protocol::assertion::read_expected_response_body,
    primary_protocol::assertion::read_replay_response_times, primary_protocol::assertion::time,
};

pub(super) fn verify(
    api: &str,
    pointers: &[String],
    assertions: &AssertionEvidence,
    rule: super::super::response::ResponseTimeRule,
) -> Result<Vec<(PathBuf, String)>> {
    let (method, path) = parse_api(api)?;
    let mut witnesses = Vec::new();
    for case in &assertions.cases {
        let Some(response) = &case.response else {
            continue;
        };
        if !response.method.eq_ignore_ascii_case(method)
            || !path_pattern_matches(path, &response.path)
        {
            continue;
        }
        let request = response
            .request
            .as_deref()
            .context("time rule preflight requires recorded request evidence")?;
        let expected = response
            .expected_response
            .as_deref()
            .context("time rule preflight requires source response evidence")?;
        let actual = response
            .actual_response
            .as_deref()
            .context("time rule preflight requires target response evidence")?;
        for path in [request, expected, actual] {
            witnesses.push((
                path.to_path_buf(),
                fingerprint(&read_published_report(path, "time rule evidence")?),
            ));
        }
        ensure!(
            response.expected_response_fingerprint.as_deref()
                == Some(witnesses[witnesses.len() - 2].1.as_str())
                && response.actual_response_fingerprint.as_deref()
                    == Some(witnesses[witnesses.len() - 1].1.as_str()),
            "response time evidence changed since assertion; run fresh Replay"
        );
        let request_document: serde_json::Value = serde_json::from_slice(&fs::read(request)?)?;
        ensure!(
            request_document["method"].as_str() == Some(method)
                && request_document["uri"]
                    .as_str()
                    .is_some_and(|uri| path_pattern_matches(
                        path,
                        &super::super::pattern::uri_path(uri)
                    )),
            "time rule request scope differs from assertion evidence"
        );
        let times = read_replay_response_times(expected, actual)?;
        let protocol = response
            .gateway_protocol
            .unwrap_or(ResponseGatewayProtocol::Http);
        ensure!(
            protocol == ResponseGatewayProtocol::Http,
            "time rule preflight requires HTTP JSON evidence"
        );
        let source = crate::json_value::parse(&read_expected_response_body(expected, protocol)?)
            .context("invalid source time response JSON")?;
        let target = crate::json_value::parse(&read_actual_response_body(actual, protocol)?)
            .context("invalid target time response JSON")?;
        for pattern in pointers {
            for pointer in super::super::response::select_json_pointers(pattern, &source, &target) {
                let left = source
                    .pointer(&pointer)
                    .context("time rule source field is missing")?;
                let right = target
                    .pointer(&pointer)
                    .context("time rule target field is missing")?;
                time::compare(rule, left, right, times).map_err(|kind| {
                    anyhow::anyhow!(
                        "response_time_preflight_failed: case={}, pointer={}, constraint={kind:?}",
                        case.case_id,
                        pointer
                    )
                })?;
            }
        }
    }
    Ok(witnesses)
}
