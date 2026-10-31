use super::*;
use crate::dependency::observation::fixture_capture;

fn catalog() -> (Catalog, Vec<Uuid>) {
    let temp = tempfile::tempdir().unwrap();
    let mut raw = Vec::new();
    let mut ids = Vec::new();
    for kind in ["case", "process", "unattributed"] {
        let capture = fixture_capture(kind);
        ids.push(capture.exchange_id);
        let event = json!({"event_type":"mysql_exchange","connection_id":Uuid::new_v4(),"query_sequence":1,
            "target_host":"mysql.test","target_port":3306,"database":"app","username":"worker",
            "command":"COM_QUERY","sql":"SELECT id FROM jobs WHERE id=1","capture":capture});
        raw.extend(serde_json::to_vec(&event).unwrap());
        raw.push(b'\n');
    }
    let path = temp.path().join("dependencies.jsonl");
    std::fs::write(&path, raw).unwrap();
    let index = crate::dependency_index::build::build_file(
        &path,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    (Catalog::from_index(&index).unwrap(), ids)
}

fn target() -> Value {
    json!({"case_id":Uuid::from_u128(44).to_string(),"resource":{"protocol":"mysql","endpoint":"mysql.test:3306","database":"app","username":"worker"},"operation":"COM_STMT_EXECUTE"})
}

#[test]
fn discovery_includes_other_cases_process_and_unattributed_without_authorizing_any() {
    let (catalog, _) = catalog();
    let result = catalog.discover(&target(), &BTreeMap::new(), 0, 2);
    assert_eq!(result["total"], 3);
    assert_eq!(result["returned"], 2);
    assert_eq!(result["next_offset"], 2);
    assert_eq!(result["exact_match_evaluated"], false);
    assert_eq!(result["consumption_authorized"], false);
    let last = catalog.discover(&target(), &BTreeMap::new(), 2, 2);
    assert_eq!(last["items"][0]["effective_owner"]["kind"], "unattributed");
    assert_eq!(
        last["items"][0]["consumption"],
        "unavailable_for_this_attempt"
    );
}

#[test]
fn effective_owner_changes_candidate_context_without_claiming_a_match() {
    let (catalog, ids) = catalog();
    let owners = BTreeMap::from([(
        ids[2],
        DependencyOwner::Case {
            origin_case_id: Uuid::from_u128(44),
            task_instance: None,
        },
    )]);
    let result = catalog.discover(&target(), &owners, 2, 1);
    assert_eq!(result["items"][0]["captured_owner"]["kind"], "unattributed");
    assert_eq!(result["items"][0]["effective_owner"]["kind"], "case");
    assert_eq!(result["items"][0]["scope_relation"], "current_case");
    assert_eq!(result["ownership_proved"], false);
}

#[test]
fn absent_resource_and_missing_metadata_are_different_facts() {
    let (catalog, _) = catalog();
    let mut request = target();
    request["resource"]["database"] = json!("different_database");
    let absent = catalog.discover(&request, &BTreeMap::new(), 0, 20);
    assert_eq!(absent["status"], "no_resource_operation_candidate");
    assert_eq!(absent["exact_match_evaluated"], false);
    assert_eq!(
        catalog.discover(&Value::Null, &BTreeMap::new(), 0, 20)["status"],
        "unavailable"
    );
}
