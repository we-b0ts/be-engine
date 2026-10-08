//! Match token-free Redis/HTTP capture witnesses to complete immutable source requests.
use super::evidence::{Witnesses, read};
use super::*;
use crate::replay::policy::{
    dynamic_values::{CaptureCandidate, DynamicValueCapture, DynamicValueFormat},
    pattern::{path_pattern_matches, uri_path},
};
use serde_json::Value;

pub(super) fn validate(
    rule: &DynamicValueRule,
    report: &Value,
    mut witnesses: Witnesses,
) -> Result<Witnesses> {
    for item in report["replay_policy"]["dynamic_capture_candidates"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let candidate: CaptureCandidate = serde_json::from_value(item.clone())?;
        if !selected(&rule.capture, &candidate.capture) {
            continue;
        }
        if rule.format.is_some_and(|format| match format {
            DynamicValueFormat::Uuid => !candidate.target_uuid,
            DynamicValueFormat::UuidV4 => !candidate.target_uuid_v4,
        }) {
            continue;
        }
        let Some(case) = report["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["case_id"] == candidate.case_id)
        else {
            continue;
        };
        let root = PathBuf::from(
            case["case_dir"]
                .as_str()
                .context("capture witness has no case directory")?,
        );
        let request: Value =
            serde_json::from_slice(&read(root.join("request.json"), &mut witnesses)?)?;
        if !path_pattern_matches(
            &rule.api,
            &uri_path(request["uri"].as_str().unwrap_or_default()),
        ) {
            continue;
        }
        let bytes = read(root.join("dependencies.jsonl"), &mut witnesses)?;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value = serde_json::from_slice(line)?;
            if event
                .get("outcome")
                .is_some_and(|outcome| outcome != "response")
            {
                continue;
            }
            let Some(source) = crate::replay::policy::dynamic_values::recorded_capture(
                &candidate.capture,
                &event,
            )?
            else {
                continue;
            };
            if fingerprint(&source.payload) != candidate.source_payload_fingerprint {
                continue;
            }
            let value = source.value;
            if fingerprint(value.as_bytes()) != candidate.source_value_fingerprint
                || candidate.source_value_fingerprint == candidate.target_value_fingerprint
            {
                continue;
            }
            rule.validate_value(&value)?;
            return Ok(witnesses);
        }
    }
    anyhow::bail!(
        "capture rule requires a current same-case Redis/HTTP witness differing only at the selected value"
    )
}

fn selected(rule: &DynamicValueCapture, candidate: &DynamicValueCapture) -> bool {
    match (rule, candidate) {
        (
            DynamicValueCapture::Http {
                target,
                method,
                path,
                json_pointer,
            },
            DynamicValueCapture::Http {
                target: other,
                method: other_method,
                path: other_path,
                json_pointer: other_pointer,
            },
        ) => {
            target == other
                && method == other_method
                && json_pointer == other_pointer
                && path_pattern_matches(path, other_path)
        }
        _ => rule == candidate,
    }
}
