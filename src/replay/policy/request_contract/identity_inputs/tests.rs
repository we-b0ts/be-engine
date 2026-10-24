use super::*;
use crate::policy::{Surface, compile_policy, parse_policy};
use crate::value_contract::identities::IdentityPair;
use serde_json::json;

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const TARGET: &str = "22222222-2222-4222-8222-222222222222";

fn owner(uri: &str, body: Option<Value>, prefix: &str, format: &str) -> RequestContracts {
    owner_with_prefixes(uri, body, &[prefix], format)
}

fn owner_with_prefixes(
    uri: &str,
    body: Option<Value>,
    prefixes: &[&str],
    format: &str,
) -> RequestContracts {
    let fields = prefixes
        .iter()
        .enumerate()
        .map(|(index, prefix)| {
            (
                if index == 0 {
                    "id".to_owned()
                } else {
                    format!("alias_{index}")
                },
                json!({"kind":"identity", "binding":"entity", "prefix":prefix, "format":format}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let document = json!({"format":"traffic-policy/v2", "resources":{"db":{
        "protocol":"mysql", "endpoint":"db.test:3306", "database":"app",
        "proof":{"source":"fixture.py:1", "fact":"Generated identifiers are copied across the declared physical fields"},
        "tables":{"tasks":{"fields":fields}}
    }}});
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
            conditions: BTreeSet::new(),
        },
    );
    owner
}

fn pair(source: &str, target: &str) -> IdentityPair {
    IdentityPair {
        domain: "entity".into(),
        source: source.into(),
        target: target.into(),
    }
}

#[test]
fn provided_id_cannot_change_in_the_first_sql_predicate_update_or_insert() {
    let owner = owner("/tasks", Some(json!({"id":SOURCE})), "", "uuid");
    let rules = owner
        .compiled_rules()
        .unwrap()
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    for template in [
        "SELECT title FROM tasks WHERE id='ID'",
        "UPDATE tasks SET title='unchanged' WHERE id='ID'",
        "INSERT INTO tasks(id,title) VALUES('ID','unchanged')",
    ] {
        let source = template.replace("ID", SOURCE);
        let target = template.replace("ID", TARGET);
        let comparison = crate::replay::policy::compare_mysql_values(
            Some("app"),
            Some(&source),
            None,
            Some(&target),
            None,
            &rules,
            Default::default(),
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
    for (body, prefix) in [
        (json!({"id":"msg_11"}), "msg_"),
        (json!({"id":11}), ""),
        (json!({"id":"11"}), ""),
    ] {
        let owner = owner("/tasks", Some(body), prefix, "decimal");
        assert!(
            owner
                .preview_identity_pairs("case", &[pair("11", "1011")])
                .is_err()
        );
    }
}

#[test]
fn prefix_only_domains_do_not_anchor_unrelated_bare_time_values() {
    let time = "1712345678901";
    for input in [
        json!({"timestamp":1712345678901u64}),
        json!({"timestamp":time}),
    ] {
        let owner = owner("/tasks", Some(input), "text-", "decimal");
        assert!(
            owner
                .preview_identity_pairs("case", &[pair(time, "1912345678901")])
                .is_ok()
        );
    }
    let provided = owner(
        "/tasks",
        Some(json!({"id":format!("text-{time}")})),
        "text-",
        "decimal",
    );
    assert!(
        provided
            .preview_identity_pairs("case", &[pair(time, "1912345678901")])
            .is_err()
    );
    let raw_alias = owner_with_prefixes(
        "/tasks",
        Some(json!({"id":1712345678901u64})),
        &["text-", ""],
        "decimal",
    );
    assert!(
        raw_alias
            .preview_identity_pairs("case", &[pair(time, "1912345678901")])
            .is_err()
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
fn incomplete_or_opaque_api_inputs_do_not_authorize_free_identity_renaming() {
    for request in [
        json!({"body":{"encoding":"utf8","data":"", "truncated":true}}),
        json!({"body":{"encoding":"utf8","data":"", "truncated":false,"decode_error":"truncated gzip"}}),
        json!({"body":{"encoding":"utf8","data":"opaque input", "truncated":false}}),
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
