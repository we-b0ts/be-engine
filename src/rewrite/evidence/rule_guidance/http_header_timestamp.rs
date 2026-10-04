//! Mechanical time-format candidates require independent source generation proof.
use super::*;

pub(super) fn candidates(facts: &Value) -> Vec<Value> {
    let mut candidates = Vec::new();
    for cluster in facts["clusters"].as_array().into_iter().flatten() {
        let difference = &cluster["representative"]["difference"];
        if cluster["protocol"] != "http" || difference["kind"] != "header_value_mismatch" {
            continue;
        }
        let source = &difference["expected"]["signature"];
        let target = &difference["actual"]["signature"];
        if source["protected"] != false || target["protected"] != false {
            continue;
        }
        let (Ok(expected), Ok(actual), Ok(source_time), Ok(target_time)) = (
            serde_json::from_value::<Vec<String>>(source["values"].clone()),
            serde_json::from_value::<Vec<String>>(target["values"].clone()),
            serde_json::from_value(source["request_started_at"].clone()),
            serde_json::from_value(target["request_started_at"].clone()),
        ) else {
            continue;
        };
        for format in [
            crate::ResponseTimestampFormat::UnixSeconds,
            crate::ResponseTimestampFormat::UnixMilliseconds,
            crate::ResponseTimestampFormat::Rfc3339,
            crate::ResponseTimestampFormat::AmzDate,
        ] {
            let selector = crate::HttpHeaderTimestampSelector {
                host: cluster["endpoint"]["host"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                port: cluster["endpoint"]["port"]
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .unwrap_or_default(),
                method: source["method"].as_str().unwrap_or_default().into(),
                path: source["uri"].as_str().unwrap_or_default().into(),
                header: source["header"].as_str().unwrap_or_default().into(),
                format,
            };
            if selector.validate().is_ok()
                && selector
                    .validate_times(&expected, &actual, source_time, target_time)
                    .is_ok()
            {
                candidates.push(serde_json::json!({"selector":selector, "tolerance_seconds":5,
                    "does_not_prove":"timestamp format and request-time proximity require source proof of current-time generation"}));
            }
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn facts() -> Value {
        json!({"clusters":[{"protocol":"http", "endpoint":{"host":"storage.example.test","port":9100},
        "representative":{"difference":{"kind":"header_value_mismatch",
            "expected":{"signature":{"header":"x-amz-date","method":"GET","uri":"/bucket/object",
                "values":["20261003T160001Z"],"protected":false,"request_started_at":"2026-10-03T16:00:01Z"}},
            "actual":{"signature":{"values":["20261005T160001Z"],"protected":false,"request_started_at":"2026-10-05T16:00:01Z"}}
        }}}]})
    }

    #[test]
    fn timestamp_header_differences_expose_the_rule_and_source_proof_requirement() {
        let mut data = facts();
        let items = candidates(&data);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["selector"]["format"], "amz_date");
        assert_eq!(items[0]["selector"]["header"], "x-amz-date");
        data["http_header_timestamp_candidates"] = json!(items);
        let hints = super::super::rule_hints(Path::new("/target"), QUERY_DIRTY_CLUSTERS, &data);
        assert!(
            hints
                .iter()
                .any(|h| h.capability == "http_header_timestamp" && h.hint.contains("source"))
        );
        let planners = super::super::applicable_rule_planners(
            Path::new("/target"),
            RewriteIssueKind::Dependency,
            QUERY_DIRTY_CLUSTERS,
            &data,
            "current",
        );
        assert!(
            planners
                .iter()
                .any(|p| p.capability == "http_header_timestamp")
        );
    }

    #[test]
    fn identity_headers_invalid_times_and_missing_clocks_do_not_offer_timestamp_rules() {
        let mut data = facts();
        let source =
            &mut data["clusters"][0]["representative"]["difference"]["expected"]["signature"];
        source["header"] = json!("x-wegent-user-id");
        source["values"] = json!(["83"]);
        assert!(candidates(&data).is_empty());
        let mut data = facts();
        data["clusters"][0]["representative"]["difference"]["actual"]["signature"]["values"] =
            json!(["20261003T160001Z"]);
        assert!(candidates(&data).is_empty());
        let mut data = facts();
        data["clusters"][0]["representative"]["difference"]["expected"]["signature"]["request_started_at"] =
            Value::Null;
        assert!(candidates(&data).is_empty());
        let mut data = facts();
        data["clusters"][0]["representative"]["difference"]["actual"]["signature"]["protected"] =
            json!(true);
        assert!(candidates(&data).is_empty());
    }
}
