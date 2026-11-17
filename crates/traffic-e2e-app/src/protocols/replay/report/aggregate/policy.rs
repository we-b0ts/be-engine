use std::path::Path;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{ReplayPolicyAggregateSummary, required_array, required_string};

pub(super) fn summary(
    report: &Value,
    report_path: &Path,
) -> Result<Option<ReplayPolicyAggregateSummary>> {
    let Some(policy) = report.get("replay_policy") else {
        return Ok(None);
    };
    let unused_applicable_dependency_rule_ids =
        required_array(policy, "unused_applicable_dependency_rule_ids", report_path)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| invalid_rule_ids(report_path))
            })
            .collect::<Result<Vec<_>>>()?;
    let expected_response = required_string(policy, "expected_response", report_path)?.to_owned();
    if expected_response != "assertions_only" {
        bail!(
            "replay report {} replay_policy.expected_response must be assertions_only",
            report_path.display()
        );
    }
    Ok(Some(ReplayPolicyAggregateSummary {
        path: required_string(policy, "path", report_path)?.to_owned(),
        fingerprint: required_string(policy, "fingerprint", report_path)?.to_owned(),
        expected_response,
        unused_applicable_dependency_rule_ids,
    }))
}

fn invalid_rule_ids(report_path: &Path) -> anyhow::Error {
    anyhow!(
        "replay report {} replay_policy.unused_applicable_dependency_rule_ids must contain strings",
        report_path.display()
    )
}
