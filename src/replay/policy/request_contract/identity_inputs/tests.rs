use super::*;
use crate::policy::{compile_policy, parse_policy};
use crate::value_contract::identities::IdentityPair;
use serde_json::json;

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const TARGET: &str = "22222222-2222-4222-8222-222222222222";

fn owner(uri: &str, body: Option<Value>, prefix: &str, format: &str) -> RequestContracts {
    let document = json!({"format":"traffic-policy/v3", "mysql":{"tables":{"tasks":{
        "pattern":"tasks", "fields":{"id":{"kind":"identity","formats":[{"prefix":prefix,"format":format}]}}
    }}}});
    let mut owner = RequestContracts::default();
    owner
        .configure_compiled(Some(Arc::new(
            compile_policy(&parse_policy(&document.to_string()).unwrap()).unwrap(),
        )))
        .unwrap();
    owner.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "POST".into(),
            path: super::super::super::pattern::uri_path(uri),
            source_uri: uri.into(),
            source_input_error: None,
            source_body: body,
            recorded: None,
            actual: None,
            dir: PathBuf::new(),
            dependencies_path: PathBuf::new(),
            conditions: BTreeSet::new(),
        },
    );
    owner
}

fn pair(source: &str, target: &str) -> IdentityPair {
    IdentityPair {
        source: serde_json::to_string(source).unwrap(),
        target: serde_json::to_string(target).unwrap(),
    }
}

#[test]
fn provided_id_cannot_change_in_the_first_sql_predicate_update_or_insert() {
    let owner = owner("/tasks", Some(json!({"id":SOURCE})), "", "uuid");
    let compiled = owner.compiled_rules().unwrap();
    let identity = crate::replay::ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    };
    for template in [
        "SELECT title FROM tasks WHERE id='ID'",
        "UPDATE tasks SET title='unchanged' WHERE id='ID'",
        "INSERT INTO tasks(id,title) VALUES('ID','unchanged')",
    ] {
        let source = template.replace("ID", SOURCE);
        let target = template.replace("ID", TARGET);
        let record = serde_json::from_value(
            json!({"command":"COM_QUERY","database":"app","sql":source,"response":{"status":"ok"}}),
        )
        .unwrap();
        let context = crate::replay::mysql::contracts::automatic::RequestContext::new(
            compiled,
            Default::default(),
            &identity,
            &record,
        );
        let comparison = crate::replay::policy::matcher::mysql_native::compare_with_automatic(
            Some("app"),
            Some(&source),
            None,
            Some(&target),
            None,
            &[],
            &[],
            Default::default(),
            None,
            &context,
        )
        .unwrap();
        assert!(comparison.passed(), "{:?}", comparison.differences);
        assert!(owner.identity_decision("case", &comparison).is_err());
        assert!(!owner.has_identities("case"));
    }
    owner
        .commit_identity(
            owner
                .preview_identity_pairs("case", &[pair(SOURCE, SOURCE)])
                .unwrap(),
        )
        .unwrap();
    assert!(
        owner
            .preview_identity_pairs("case", &[pair(SOURCE, TARGET)])
            .is_err()
    );
}

#[test]
fn exact_decoded_path_query_json_and_numeric_inputs_are_fixed_anchors() {
    for (uri, body) in [
        (format!("/tasks/{SOURCE}"), None),
        (format!("/tasks/%31{}", &SOURCE[1..]), None),
        (format!("/tasks?id={SOURCE}"), None),
        (format!("/tasks?id=%31{}", &SOURCE[1..]), None),
        ("/tasks".into(), Some(json!({"nested":[{"id":SOURCE}]}))),
    ] {
        let owner = owner(&uri, body, "", "uuid");
        assert!(
            owner
                .preview_identity_pairs("case", &[pair(SOURCE, TARGET)])
                .is_err()
        );
    }
    for (body, prefix, source, target) in [
        (
            json!({"id":"msg_11"}),
            "msg_",
            json!("msg_11"),
            json!("msg_1011"),
        ),
        (json!({"id":11}), "", json!(11), json!(1011)),
        (json!({"id":"11"}), "", json!("11"), json!("1011")),
    ] {
        let owner = owner("/tasks", Some(body), prefix, "decimal");
        let pair = IdentityPair {
            source: serde_json::to_string(&source).unwrap(),
            target: serde_json::to_string(&target).unwrap(),
        };
        assert!(owner.preview_identity_pairs("case", &[pair]).is_err());
    }
}

#[test]
fn full_prefix_and_scalar_type_keep_unrelated_input_values_distinct() {
    let contracts = owner(
        "/tasks",
        Some(json!({"timestamp":"11", "number":11})),
        "text-",
        "decimal",
    );
    assert!(
        contracts
            .preview_identity_pairs("case", &[pair("text-11", "text-1011")])
            .is_ok()
    );
    let contracts = owner("/tasks", Some(json!({"id":"text-11"})), "text-", "decimal");
    assert!(
        contracts
            .preview_identity_pairs("case", &[pair("text-11", "text-1011")])
            .is_err()
    );
    let contracts = owner("/tasks", Some(json!({"id":11})), "", "decimal");
    assert!(
        contracts
            .preview_identity_pairs("case", &[pair("11", "1011")])
            .is_ok()
    );
}

#[test]
fn generated_ids_absent_from_inputs_remain_eligible_and_substrings_do_not_anchor() {
    let owner = owner(
        "/tasks",
        Some(json!({"text":format!("prefix-{SOURCE}-suffix"), "stable":7})),
        "",
        "uuid",
    );
    let pending = owner
        .preview_identity_pairs("case", &[pair(SOURCE, TARGET)])
        .unwrap();
    assert!(!owner.has_identities("case"));
    owner.commit_identity(pending).unwrap();
    assert!(owner.has_identities("case"));
}

#[test]
fn empty_time_only_comparisons_do_not_build_or_lock_identity_state() {
    let owner = owner("/tasks", Some(json!({"large":vec![0;20000]})), "", "uuid");
    let empty = owner
        .identity_decision("case", &Default::default())
        .unwrap();
    assert!(empty.is_empty());
    owner.commit_identity(empty).unwrap();
    assert!(owner.state.lock().unwrap().identity_inputs.is_empty());
    assert!(
        owner
            .preview_identity_pairs("case", &[pair(SOURCE, TARGET)])
            .is_err()
    );
    assert_eq!(owner.state.lock().unwrap().identity_inputs.len(), 1);
    owner.clear_identities("case");
    assert!(owner.state.lock().unwrap().identity_inputs.is_empty());
}

#[test]
fn input_index_fails_closed_on_bounds_and_invalid_path_escapes() {
    for uri in ["/tasks/%", "/tasks/%ff"] {
        let index = InputIndex::build(uri, None);
        assert!(index.failure.is_some());
        assert!(index.values.is_empty());
    }
    let index = InputIndex::build("/tasks", Some(&json!({"text":"x".repeat(MAX_INPUT_BYTES)})));
    assert!(index.failure.is_some());
    assert!(index.values.is_empty());
}

#[test]
fn incomplete_or_redacted_api_inputs_do_not_authorize_identity_renaming() {
    for request in [
        json!({"body":{"encoding":"utf8","data":"", "truncated":true}}),
        json!({"body":{"encoding":"utf8","data":"", "truncated":false,"decode_error":"truncated gzip"}}),
        json!({"body":{"encoding":"utf8","data":"", "truncated":false,"redacted":true}}),
    ] {
        let owner = owner("/tasks", None, "", "uuid");
        owner
            .state
            .lock()
            .unwrap()
            .cases
            .get_mut("case")
            .unwrap()
            .source_input_error = capture_error(&request, None);
        assert!(
            owner
                .preview_identity_pairs("case", &[pair(SOURCE, TARGET)])
                .is_err()
        );
        assert!(
            owner
                .preview_identity_pairs("case", &[pair(SOURCE, SOURCE)])
                .is_ok()
        );
    }
    assert!(
        capture_error(
            &json!({"body":{"encoding":"utf8","data":"", "truncated":false}}),
            None
        )
        .is_none()
    );
}

#[test]
fn complete_opaque_multipart_inputs_keep_independently_generated_ids_eligible() {
    let request = json!({"body":{"encoding":"utf8","truncated":false,
        "data":"--file-boundary\r\nContent-Disposition: form-data; name=upload; filename=photo.png\r\n\r\nopaque bytes\r\n--file-boundary--"}});
    for uri in [
        "/uploads".to_string(),
        format!("/uploads/{SOURCE}"),
        format!("/uploads?id={SOURCE}"),
    ] {
        let owner = owner(&uri, None, "", "uuid");
        owner
            .state
            .lock()
            .unwrap()
            .cases
            .get_mut("case")
            .unwrap()
            .source_input_error = capture_error(&request, None);
        let generated = owner.preview_identity_pairs("case", &[pair(SOURCE, TARGET)]);
        assert_eq!(generated.is_ok(), uri == "/uploads");
    }
}
