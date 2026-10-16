use super::*;
use serde_json::json;

#[test]
fn literal_groups_keep_trailing_paths_and_404_oracles_distinct_and_immutable() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("cases");
    let paths = [
        ("plain", "/api/items"),
        ("slash", "/api/items/"),
        ("repeated", "/api//items"),
    ];
    let mut originals = Vec::new();
    for (id, path) in paths {
        let case = write_case(&source, "shared", id, "GET", path);
        let body = if id == "plain" {
            r#"{"ok":true}"#
        } else {
            r#"{"detail":"Not Found"}"#
        };
        fs::write(case.join("expected-response.json"),json!({"status":if id=="plain"{200}else{404},"body":{"encoding":"utf8","data":body,"truncated":false}}).to_string()).unwrap();
        originals.push((
            case.clone(),
            fs::read(case.join("request.json")).unwrap(),
            fs::read(case.join("expected-response.json")).unwrap(),
        ));
    }
    let output = temp.path().join("groups.json");
    for (id, path) in paths {
        let result = ensure_case_group(options(
            &source,
            &source.join("shared"),
            &output,
            path,
            None,
        ))
        .unwrap();
        assert_eq!(result.case_ids, [id]);
        assert_eq!(result.source_route, path);
        assert_eq!(result.group_id, format!("GET {path}"));
    }
    let inventory = load_complete_case_group_inventory(&output, &source).unwrap();
    assert_eq!(inventory.groups.len(), 3);
    let selected =
        crate::resolve_recording_api_case_ids(&source, &["GET /api/items/".parse().unwrap()])
            .unwrap();
    assert_eq!(selected, ["slash"]);
    let policy = temp.path().join("policy.yaml");
    fs::write(&policy, "format: traffic-policy/v1\nrules: []\n").unwrap();
    let actual = temp.path().join("actual.json");
    let slash = source.join("shared/slash");
    for (status, body, passes) in [
        (404, r#"{"detail":"Not Found"}"#, true),
        (200, r#"{"detail":"Not Found"}"#, false),
        (307, r#"{"detail":"Not Found"}"#, false),
        (404, r#"{"detail":"changed"}"#, false),
    ] {
        fs::write(&actual,json!({"version":1,"status":status,"body":{"encoding":"utf8","data":body,"truncated":false}}).to_string()).unwrap();
        let report = crate::assert_recorded_response(crate::ResponseAssertionOptions {
            case_id: "slash".into(),
            request: slash.join("request.json"),
            expected_response: slash.join("expected-response.json"),
            actual_response: actual.clone(),
            policy: policy.clone(),
        })
        .unwrap();
        assert_eq!(report.passed, passes);
    }
    for (case, request, expected) in originals {
        assert_eq!(fs::read(case.join("request.json")).unwrap(), request);
        assert_eq!(
            fs::read(case.join("expected-response.json")).unwrap(),
            expected
        );
    }
}
