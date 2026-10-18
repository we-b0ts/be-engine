//! Reconcile rule applicability with the final ownership of its exact Source
//! exchanges. Rule usage and exchanges still owned by a Case remain mandatory.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{MATCHED_RULE, ORIGINAL_CASE_ID};

pub(super) fn reclassify(report: &mut Value) {
    let background = report["unused_global_exchanges"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| {
            event[MATCHED_RULE].is_string()
                && event["case_id"].is_null()
                && event["source"] == "global"
        })
        .filter_map(|event| {
            Some((
                event[ORIGINAL_CASE_ID].as_str()?.to_owned(),
                event["index"].as_u64()?,
            ))
        })
        .collect::<BTreeSet<_>>();
    let Some(policy) = report.get_mut("replay_policy") else {
        return;
    };
    let Some(sources) = policy["recorded_mysql_rule_applicability"].as_object() else {
        // Older reports have no occurrence proof. Never remove their obligation
        // by guessing from a rule id, SQL preview or a background counter.
        return;
    };
    let sources = sources
        .iter()
        .filter_map(|(id, values)| {
            let values = values
                .as_array()?
                .iter()
                .map(|value| {
                    Some((
                        value["case_id"].as_str()?.to_owned(),
                        value["index"].as_u64()?,
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            (!values.is_empty()).then_some((id.clone(), values))
        })
        .collect::<BTreeMap<_, _>>();
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
        if rule["protocol"] != "mysql" {
            continue;
        }
        let Some(witnesses) = rule["id"].as_str().and_then(|id| sources.get(id)) else {
            continue;
        };
        // Positive Target use is independent evidence and must survive even if
        // every unused Source occurrence was classified as process-owned.
        let Some(matches) = rule["matches"].as_u64() else {
            continue;
        };
        rule["applicable"] =
            json!(matches > 0 || witnesses.iter().any(|w| !background.contains(w)));
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
