//! Read original case witnesses from the reversible report overlay.
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{MATCHED_RULE, ORIGINAL_CASE_ID};

pub(crate) fn parse_background_dependency_evidence<T: DeserializeOwned>(
    raw: &str,
) -> serde_json::Result<T> {
    let mut report = serde_json::from_str(raw)?;
    restore_previous_reclassification(&mut report);
    serde_json::from_value(report)
}

pub(super) fn restore_previous_reclassification(report: &mut Value) {
    restore_array(report, "unused_global_exchanges", "unused_case_exchanges");
    restore_array(
        report,
        "unused_global_http_exchanges",
        "unused_case_http_exchanges",
    );
    for protocol in ["redis", "memcached", "motan"] {
        let Some(protocol_report) = report.get_mut(protocol) else {
            continue;
        };
        restore_array(protocol_report, "unused_global", "unused_case");
    }
}

fn restore_array(report: &mut Value, global_field: &str, case_field: &str) {
    let Some(object) = report.as_object_mut() else {
        return;
    };
    let mut global = object
        .remove(global_field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut case = object
        .remove(case_field)
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let mut retained = Vec::with_capacity(global.len());
    for mut event in global.drain(..) {
        let original_case = event
            .get(ORIGINAL_CASE_ID)
            .and_then(Value::as_str)
            .filter(|_| {
                event.get(MATCHED_RULE).and_then(Value::as_str).is_some()
                    && event.get("case_id") == Some(&Value::Null)
                    && event.get("source").and_then(Value::as_str) == Some("global")
            })
            .map(ToOwned::to_owned);
        if let Some(original_case) = original_case {
            if let Some(event) = event.as_object_mut() {
                event.insert("case_id".to_string(), Value::String(original_case));
                event.insert("source".to_string(), Value::String("case".to_string()));
                event.remove(ORIGINAL_CASE_ID);
                event.remove(MATCHED_RULE);
            }
            case.push(event);
        } else {
            retained.push(event);
        }
    }
    object.insert(global_field.to_string(), Value::Array(retained));
    object.insert(case_field.to_string(), Value::Array(case));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn original_witness_projection_is_idempotent_for_every_overlay_protocol() {
        let marked = json!({"case_id":null,"source":"global",
            "background_original_case_id":"case-a","background_rule":"startup"});
        let native = json!({"case_id":null,"source":"global"});
        let incomplete = json!({"case_id":null,"background_original_case_id":"case-b"});
        let mut report = json!({
            "unused_global_exchanges":[marked,native,incomplete],
            "unused_global_http_exchanges":[marked,native,incomplete],
            "unmatched_http_requests":[{"case_id":"case-a"}]
        });
        for protocol in ["redis", "memcached", "motan"] {
            report[protocol] = json!({"unused_global":[marked,native,incomplete]});
        }
        let projected: Value = parse_background_dependency_evidence(&report.to_string()).unwrap();
        assert_eq!(
            projected["unmatched_http_requests"],
            report["unmatched_http_requests"]
        );
        for (part, case, global) in [
            (
                &projected,
                "unused_case_exchanges",
                "unused_global_exchanges",
            ),
            (
                &projected,
                "unused_case_http_exchanges",
                "unused_global_http_exchanges",
            ),
            (&projected["redis"], "unused_case", "unused_global"),
            (&projected["memcached"], "unused_case", "unused_global"),
            (&projected["motan"], "unused_case", "unused_global"),
        ] {
            assert_eq!(part[case], json!([{"case_id":"case-a","source":"case"}]));
            assert_eq!(part[global], json!([native, incomplete]));
        }
        let repeated: Value = parse_background_dependency_evidence(&projected.to_string()).unwrap();
        assert_eq!(repeated, projected);
    }
}
