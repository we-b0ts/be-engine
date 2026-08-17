use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use super::{QUERY_REPRESENTATIVES, RewriteState};
use crate::replay::{
    is_motan_hessian2_body, is_motan_protobuf_body, motan_hessian2_envelope_name,
    read_comparison_response_observation,
};

pub(super) fn enrich_protocol_candidate(
    state: &RewriteState,
    query_kind: &str,
    facts: &mut Value,
) -> Result<()> {
    let motan = facts.pointer("/comparison_observation/motan");
    let already_current = motan.is_some_and(|motan| {
        motan.get("configured").and_then(Value::as_bool) == Some(true)
            || motan
                .get("protocol_candidates")
                .and_then(Value::as_array)
                .is_some_and(|candidates| !candidates.is_empty())
    });
    if query_kind != QUERY_REPRESENTATIVES || !state.api.starts_with("MOTAN ") || already_current {
        return Ok(());
    }
    let observation = facts
        .get("comparison_observation")
        .filter(|value| !value.is_null());
    let eligible = observation.is_some_and(|observation| {
        observation.get("classification").and_then(Value::as_str) == Some("candidate_difference")
            && observation.get("pointer").and_then(Value::as_str) == Some("$body")
            && observation.get("difference_kind").and_then(Value::as_str)
                == Some("exact_body_mismatch")
    });
    if !eligible {
        return Ok(());
    }
    let case_dir = facts
        .pointer("/representative/case_dir")
        .and_then(Value::as_str)
        .context("comparison representative has no case directory")?;
    let case_dir = Path::new(case_dir);
    let expected = read_comparison_response_observation(
        &case_dir.join("expected-response.json"),
        "source-before response",
    )?;
    let actual = read_comparison_response_observation(
        &case_dir.join("response.json"),
        "candidate response",
    )?;
    let mut protocol_candidates = Vec::new();
    if is_motan_protobuf_body(&expected.body) && is_motan_protobuf_body(&actual.body) {
        protocol_candidates.push("protobuf");
    }
    if is_motan_hessian2_body(&expected.body) && is_motan_hessian2_body(&actual.body) {
        protocol_candidates.push("hessian2");
    }
    if let Some(protocol) = protocol_candidates.first().copied() {
        let envelope = match protocol {
            "hessian2" => motan_hessian2_envelope_name(&expected.body).unwrap_or("raw"),
            _ => "simple_byte_array",
        };
        let observation = facts
            .get_mut("comparison_observation")
            .and_then(Value::as_object_mut)
            .context("comparison observation is not an object")?;
        let motan = observation
            .entry("motan")
            .or_insert_with(|| serde_json::json!({}));
        if motan.is_null() {
            *motan = serde_json::json!({});
        }
        let motan = motan
            .as_object_mut()
            .context("comparison Motan observation is not an object")?;
        motan
            .entry("rule_kind")
            .or_insert_with(|| Value::String("motan".to_string()));
        motan
            .entry("protocol")
            .or_insert_with(|| Value::String(protocol.to_string()));
        motan.insert(
            "protocol_candidates".to_string(),
            serde_json::json!(protocol_candidates),
        );
        motan
            .entry("envelope")
            .or_insert_with(|| Value::String(envelope.to_string()));
        motan
            .entry("configured")
            .or_insert_with(|| Value::Bool(false));
    }
    Ok(())
}

pub(super) fn protocol_candidates(facts: &Value) -> Vec<&'static str> {
    let motan = facts.pointer("/comparison_observation/motan");
    let configured = motan
        .and_then(|motan| motan.get("configured"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if configured {
        return match motan
            .and_then(|motan| motan.get("protocol"))
            .and_then(Value::as_str)
        {
            Some("protobuf") => vec!["protobuf"],
            Some("hessian2") => vec!["hessian2"],
            _ => Vec::new(),
        };
    }
    let candidates = motan
        .and_then(|motan| motan.get("protocol_candidates"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let supported = ["protobuf", "hessian2"]
        .into_iter()
        .filter(|supported| {
            candidates
                .iter()
                .any(|candidate| candidate.as_str() == Some(*supported))
        })
        .collect::<Vec<_>>();
    if supported.is_empty() {
        match motan
            .and_then(|motan| motan.get("protocol"))
            .and_then(Value::as_str)
        {
            Some("protobuf") => vec!["protobuf"],
            Some("hessian2") => vec!["hessian2"],
            _ => Vec::new(),
        }
    } else {
        supported
    }
}
