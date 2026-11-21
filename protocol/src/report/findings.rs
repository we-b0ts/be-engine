//! Standard candidate observations carry opaque registered-policy findings.
use serde_json::{Value, json};

pub fn candidate_findings(event: &Value, protocol: &str) -> Vec<Value> {
    let mut findings = Vec::new();
    for candidate in event["candidate_comparisons"]
        .as_array()
        .into_iter()
        .flatten()
    {
        for finding in candidate["policy_findings"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let mut finding = finding.clone();
            let Some(fields) = finding.as_object_mut() else {
                continue;
            };
            fields.insert(
                "origin".into(),
                json!({
                    "protocol":protocol,"target_observation_id":event["target_observation_id"],
                    "source_reference":candidate["source_reference"],
                    "source_exchange_id":candidate["source_exchange_id"],
                    "source_case_id":candidate["source_case_id"],
                    "source":candidate["source"]
                }),
            );
            findings.push(finding);
        }
    }
    findings
}

pub(super) fn representative_findings(facts: &Value) -> Vec<Value> {
    facts["clusters"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|cluster| {
            ["expected", "actual"].into_iter().flat_map(move |side| {
                candidate_findings(
                    &cluster["representative"]["difference"][side]["signature"],
                    cluster["protocol"].as_str().unwrap_or_default(),
                )
            })
        })
        .take(20)
        .collect()
}
