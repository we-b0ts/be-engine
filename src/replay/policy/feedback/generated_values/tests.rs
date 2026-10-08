use super::*;
use crate::replay::{ResponseAssertionOptions, assert_recorded_response};
use serde_json::{Value, json};

fn write(path: &std::path::Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn header_rule() -> ResponseHeaderDateRule {
    serde_json::from_value(json!({"header":"content-disposition","parameter":"filename","format":"%Y-%m-%d","timezone":"+00:00","source_evidence":"Exporter:filename appends the current UTC calendar date"})).unwrap()
}
fn header_fixture() -> (
    tempfile::TempDir,
    ResponseAssertionOptions,
    ResponseHeaderDateRuleFeedback,
) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let options = ResponseAssertionOptions {
        case_id: "case".into(),
        request: root.join("request.json"),
        expected_response: root.join("expected-response.json"),
        actual_response: root.join("actual-response.json"),
        policy: root.join("verification.yaml"),
    };
    fs::write(
        &options.policy,
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    write(
        &options.request,
        &json!({"method":"GET","uri":"/download","timestamp":"2026-10-07T12:00:00Z"}),
    );
    write(
        &options.expected_response,
        &json!({"status":200,"headers":{"content-disposition":["attachment; filename=report_2026-10-07.docx"]},"body":{"encoding":"utf8","data":"{\"stable\":1}","truncated":false}}),
    );
    write(
        &options.actual_response,
        &json!({"version":1,"status":200,"request_sent_at":"2026-10-08T12:00:00Z","headers":{"content-disposition":["attachment; filename=report_2026-10-08.docx"]},"body":{"encoding":"utf8","data":"{\"stable\":1}","truncated":false}}),
    );
    let report = assert_recorded_response(copy_options(&options)).unwrap();
    assert!(!report.passed);
    assert_eq!(report.header_date_candidates.len(), 1);
    let detail = root.join("detail.json");
    let bytes = serde_json::to_vec(&report).unwrap();
    fs::write(&detail, &bytes).unwrap();
    let assertion_report = root.join("assertions.json");
    let aggregate_report = root.join("aggregate.json");
    write(
        &assertion_report,
        &json!({"version":4,"case_source":root,"expected_response":"assertions_only","assertion_mode":"runner_owned","policy_fingerprint":report.policy_fingerprint,"cases":[{"case_id":"case","response":{"method":"GET","path":"/download","detail_report":detail,"detail_fingerprint":fingerprint(&bytes)}}]}),
    );
    write(
        &aggregate_report,
        &json!({"case_source":root,"selected_case_ids":["case"],"complete":true,"dirty":false}),
    );
    let feedback = ResponseHeaderDateRuleFeedback {
        policy_path: options.policy.clone(),
        api: "/download".into(),
        rules: vec![header_rule()],
        evidence: ResponseBodyRuleEvidence::FocusedE2e {
            assertion_report,
            aggregate_report,
        },
    };
    (temp, options, feedback)
}

#[test]
fn header_plan_apply_replay_keeps_body_and_filename_validation_strict() {
    let (_temp, options, feedback) = header_fixture();
    let original = fs::read(&options.expected_response).unwrap();
    let plan = plan_response_header_date_rule(feedback).unwrap();
    assert!(plan.report().requires_fresh_replay);
    plan.apply().unwrap();
    let report = assert_recorded_response(copy_options(&options)).unwrap();
    assert!(report.passed, "{:?}", report.differences);
    assert_eq!(report.applied_header_rule_ids.len(), 1);
    assert_eq!(fs::read(&options.expected_response).unwrap(), original);
    let mut response: Value =
        serde_json::from_slice(&fs::read(&options.actual_response).unwrap()).unwrap();
    response["body"]["data"] = json!("{\"stable\":2}");
    write(&options.actual_response, &response);
    assert!(
        !assert_recorded_response(copy_options(&options))
            .unwrap()
            .passed
    );
    response["body"]["data"] = json!("{\"stable\":1}");
    response["headers"]["content-disposition"] =
        json!(["attachment; filename=report_2026-10-09.docx"]);
    write(&options.actual_response, &response);
    let report = assert_recorded_response(options).unwrap();
    assert!(!report.passed);
    assert_eq!(report.unused_applicable_header_rule_ids.len(), 1);
}

#[test]
fn header_authoring_rejects_stale_artifacts_both_before_plan_and_before_apply() {
    for before_plan in [false, true] {
        let (_temp, options, feedback) = header_fixture();
        let original = fs::read(&options.policy).unwrap();
        let plan = (!before_plan).then(|| plan_response_header_date_rule(feedback).unwrap());
        let mut bytes = fs::read(&options.actual_response).unwrap();
        bytes.push(b' ');
        fs::write(&options.actual_response, bytes).unwrap();
        if let Some(plan) = plan {
            assert!(plan.apply().is_err());
        } else {
            // Rebuild the current contract fixture, then change a referenced response.
            let (_temp, options, feedback) = header_fixture();
            let mut bytes = fs::read(&options.actual_response).unwrap();
            bytes.push(b' ');
            fs::write(&options.actual_response, bytes).unwrap();
            assert!(plan_response_header_date_rule(feedback).is_err());
        }
        assert_eq!(fs::read(options.policy).unwrap(), original);
    }
}

fn dynamic_fixture() -> (tempfile::TempDir, DynamicValueRuleFeedback, Value) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let case = root.join("case");
    fs::create_dir(&case).unwrap();
    let policy_path = root.join("verification.yaml");
    fs::write(
        &policy_path,
        "# preserved\nversion: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    write(
        &case.join("request.json"),
        &json!({"method":"POST","uri":"/items"}),
    );
    let source = json!({"event_type":"mysql_exchange","target_host":"db.internal","target_port":3306,"database":"app","username":"user","command":"COM_QUERY","sql":"SELECT id FROM kinds WHERE name='old-name' AND uid=7","parse_warnings":[],"response":{"status":"resultset","columns":[{"name":"id","family":"integer","sql_type":"BIGINT"}],"rows":[]}});
    fs::write(case.join("dependencies.jsonl"), source.to_string()).unwrap();
    let replay_report = root.join("replay.json");
    write(
        &replay_report,
        &json!({"finalized":true,"replay_policy":{"fingerprint":load_replay_policy(&policy_path).unwrap().fingerprint},"cases":[{"case_id":"case","case_dir":case}],"unmatched_queries":[{"case_id":"case","command":"COM_STMT_EXECUTE","target":{"host":"db.internal","port":3306},"database":"app","username":"user","sql":"SELECT id FROM kinds WHERE name=? AND uid=?","params":[{"kind":"string","value":"new-name"},{"kind":"integer","value":7}]}]}),
    );
    let rule = serde_json::from_value(json!({"id":"name","api":"/items","targets":[{"host":"db.internal","port":3306},{"host":"redis.internal","port":6379}],"capture":{"protocol":"mysql","target":{"host":"db.internal","port":3306},"database":"app","sql":"SELECT id FROM kinds WHERE name=? AND uid=?","value_index":0},"source_evidence":"NameFactory:create generates a random name shared by SQL and Redis"})).unwrap();
    (
        temp,
        DynamicValueRuleFeedback {
            policy_path,
            rule,
            replay_report,
        },
        source,
    )
}

#[test]
fn dynamic_plan_requires_complete_capture_and_changes_only_policy() {
    for mutation in [
        "valid",
        "truncated",
        "missing_columns",
        "stable_filter",
        "case_scope",
        "stale_policy",
    ] {
        let (temp, mut feedback, mut source) = dynamic_fixture();
        match mutation {
            "truncated" => source["response"]["rows_truncated"] = json!(true),
            "missing_columns" => source["response"]["columns"] = json!([]),
            "stable_filter" => {
                source["sql"] = json!("SELECT id FROM kinds WHERE name='old-name' AND uid=8")
            }
            "case_scope" => feedback.rule.api = "/other".into(),
            "stale_policy" => fs::write(
                &feedback.policy_path,
                "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
            )
            .unwrap(),
            _ => (),
        }
        let dependencies = temp.path().join("case/dependencies.jsonl");
        fs::write(&dependencies, source.to_string()).unwrap();
        let immutable = fs::read(&dependencies).unwrap();
        let policy_path = feedback.policy_path.clone();
        let result = plan_dynamic_value_rule(feedback);
        if mutation == "valid" {
            result.unwrap().apply().unwrap();
            assert!(
                fs::read_to_string(policy_path)
                    .unwrap()
                    .starts_with("# preserved\n")
            );
        } else {
            assert!(result.is_err(), "{mutation}");
        }
        assert_eq!(fs::read(dependencies).unwrap(), immutable);
    }
}

fn copy_options(options: &ResponseAssertionOptions) -> ResponseAssertionOptions {
    ResponseAssertionOptions {
        case_id: options.case_id.clone(),
        request: options.request.clone(),
        expected_response: options.expected_response.clone(),
        actual_response: options.actual_response.clone(),
        policy: options.policy.clone(),
    }
}
