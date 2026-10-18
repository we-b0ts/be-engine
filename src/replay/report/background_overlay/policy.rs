//! Reconcile rule applicability with the final ownership of its exact Source
//! exchanges. Rule usage and exchanges still owned by a Case remain mandatory.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{MATCHED_RULE, ORIGINAL_CASE_ID};

pub(super) fn reclassify(report: &mut Value) {
    let mysql_background = background_events(&report["unused_global_exchanges"])
        .filter_map(|event| {
            Some((
                event[ORIGINAL_CASE_ID].as_str()?.to_owned(),
                event["index"].as_u64()?,
            ))
        })
        .collect::<BTreeSet<_>>();
    let redis_background = background_events(&report["redis"]["unused_global"])
        .filter_map(|event| redis_identity(event, ORIGINAL_CASE_ID))
        .collect::<BTreeSet<_>>();
    let Some(policy) = report.get_mut("replay_policy") else {
        return;
    };
    let mysql = source_obligations(
        &policy["recorded_mysql_rule_applicability"],
        &mysql_background,
        |event| {
            Some((
                event["case_id"].as_str()?.to_owned(),
                event["index"].as_u64()?,
            ))
        },
    );
    let redis = source_obligations(
        &policy["recorded_redis_rule_applicability"],
        &redis_background,
        |event| redis_identity(event, "case_id"),
    );
    if mysql.is_empty() && redis.is_empty() {
        // Legacy or incomplete reports have no occurrence proof. Never remove
        // their obligations by guessing from a rule id or background count.
        return;
    }
    let previous_unused = policy["unused_applicable_dependency_rule_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let Some(rules) = policy["dependency_rules"].as_array_mut() else {
        return;
    };
    for rule in rules.iter_mut() {
        let sources = match rule["protocol"].as_str() {
            Some("mysql") => &mysql,
            Some("redis") => &redis,
            _ => continue,
        };
        let Some(required) = rule["id"].as_str().and_then(|id| sources.get(id)) else {
            continue;
        };
        // Positive Target use is independent evidence and must survive even if
        // every unused Source occurrence was classified as process-owned.
        let Some(matches) = rule["matches"].as_u64() else {
            continue;
        };
        rule["applicable"] = json!(matches > 0 || *required);
    }
    let known = rules
        .iter()
        .filter_map(|rule| rule["id"].as_str())
        .collect::<BTreeSet<_>>();
    let unused = rules
        .iter()
        .filter(|rule| rule["applicable"] == true && rule["matches"] == 0)
        .filter_map(|rule| rule["id"].as_str().map(ToOwned::to_owned))
        .chain(
            previous_unused
                .into_iter()
                .filter(|id| !known.contains(id.as_str())),
        )
        .collect::<Vec<_>>();
    policy["unused_applicable_dependency_rule_ids"] = json!(unused);
}

fn background_events(events: &Value) -> impl Iterator<Item = &Value> {
    events.as_array().into_iter().flatten().filter(|event| {
        event[MATCHED_RULE].is_string() && event["case_id"].is_null() && event["source"] == "global"
    })
}

fn redis_identity(event: &Value, case_field: &str) -> Option<(String, String, u64)> {
    let case = event[case_field].as_str().filter(|case| !case.is_empty())?;
    let connection = event["connection_id"]
        .as_str()
        .filter(|connection| !connection.is_empty())?;
    let sequence = event["sequence"]
        .as_u64()
        .filter(|sequence| *sequence > 0)?;
    Some((case.into(), connection.into(), sequence))
}

fn source_obligations<T: Ord>(
    sources: &Value,
    background: &BTreeSet<T>,
    identity: impl Fn(&Value) -> Option<T>,
) -> BTreeMap<String, bool> {
    sources
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(id, values)| {
            let values = values
                .as_array()?
                .iter()
                .map(&identity)
                .collect::<Option<Vec<_>>>()?;
            (!values.is_empty()).then(|| {
                (
                    id.clone(),
                    values.iter().any(|value| !background.contains(value)),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
