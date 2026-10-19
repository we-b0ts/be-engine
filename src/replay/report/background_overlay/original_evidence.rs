//! Read original case witnesses from the reversible report overlay.
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{MATCHED_RULE, ORIGINAL_CASE_ID, take_array};

pub(crate) fn parse_background_dependency_evidence<T: DeserializeOwned>(
    raw: &str,
) -> serde_json::Result<T> {
    let mut report = serde_json::from_str(raw)?;
    restore_previous_reclassification(&mut report);
    serde_json::from_value(report)
}

pub(super) fn restore_previous_reclassification(report: &mut Value) {
    if let Some(object) = report.as_object_mut() {
        let owned = take_array(object, "process_owned_mysql_exchanges");
        if !owned.is_empty() {
            let mut case = take_array(object, "unused_case_exchanges");
            for mut exchange in owned {
                if let Some(fields) = exchange.as_object_mut() {
                    fields.remove("ownership_rule");
                    fields.remove("trigger_case_id");
                }
                case.push(exchange);
            }
            object.insert("unused_case_exchanges".into(), Value::Array(case));
        }
    }
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
    super::policy::reclassify(report);
}

fn restore_array(report: &mut Value, global_field: &str, case_field: &str) {
    let Some(object) = report.as_object_mut() else {
        return;
    };
    let mut global = take_array(object, global_field);
    let mut case = take_array(object, case_field);
    let mut retained = Vec::with_capacity(global.len());
    let original_len = global.len();
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
                event.remove("api_trigger_source");
            }
            case.push(event);
        } else {
            retained.push(event);
        }
    }
    update_global_count(object, global_field, original_len, retained.len());
    object.insert(global_field.to_string(), Value::Array(retained));
    object.insert(case_field.to_string(), Value::Array(case));
}

pub(super) fn update_global_count(
    object: &mut serde_json::Map<String, Value>,
    global_field: &str,
    before: usize,
    after: usize,
) {
    let count = match global_field {
        "unused_global_exchanges" => "unused_global_exchange_count",
        "unused_global_http_exchanges" => "unused_global_http_exchange_count",
        "unused_global" => "unused_global_count",
        _ => return,
    };
    if let Some(total) = object.get(count).and_then(Value::as_u64) {
        object.insert(
            count.into(),
            total
                .saturating_sub(before as u64)
                .saturating_add(after as u64)
                .into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_mysql_ownership_is_restored_before_current_policy_is_applied() {
        let mut report = json!({"process_owned_mysql_exchanges":[{"case_id":"case-a","index":624,
            "command":"COM_QUERY","connection_id":"connection","query_sequence":411,
            "ownership_rule":"old-rule","trigger_case_id":"origin"}],"unused_case_exchanges":[]});
        restore_previous_reclassification(&mut report);
        assert_eq!(report["unused_case_exchanges"][0]["index"], 624);
        assert!(
            report["unused_case_exchanges"][0]
                .get("ownership_rule")
                .is_none()
        );
        assert!(
            report["unused_case_exchanges"][0]
                .get("trigger_case_id")
                .is_none()
        );
        assert!(report["process_owned_mysql_exchanges"].is_null());
        let expected = report.clone();
        restore_previous_reclassification(&mut report);
        assert_eq!(report, expected);
    }

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
        report["unused_global_exchange_count"] = 10003.into();
        report["unused_global_http_exchange_count"] = 20003.into();
        for protocol in ["redis", "memcached", "motan"] {
            report[protocol] =
                json!({"unused_global":[marked,native,incomplete],"unused_global_count":30003});
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
        assert_eq!(projected["unused_global_exchange_count"], 10002);
        assert_eq!(projected["unused_global_http_exchange_count"], 20002);
        assert_eq!(projected["redis"]["unused_global_count"], 30002);
    }
}
