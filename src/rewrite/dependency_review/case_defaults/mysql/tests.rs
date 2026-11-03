use super::*;
use serde_json::json;

fn case() -> Uuid {
    Uuid::from_u128(1)
}

fn event(seq: u64, owner: Option<Uuid>, before: u16, after: u16) -> Value {
    let connection = Uuid::from_u128(10);
    let at = Utc::now();
    json!({
        "event_type":"mysql_exchange", "timestamp":at, "duration_ms":1,
        "target_host":"mysql.test", "target_port":3306, "database":"app", "username":"app",
        "connection_id":connection,"query_sequence":seq,"command":"COM_QUERY",
        "sql":if owner.is_some(){"SELECT id FROM tasks"}else{"ROLLBACK"},
        "params":null,"outcome":"response","server_status_before":before,"parse_warnings":[],
        "response":{"status":"ok","server_status":after,"error_code":null,"error_message":null,
            "affected_rows":0,"last_insert_id":0,"row_count":0,"rows_truncated":false,"rows":[],"columns":[]},
        "capture":{"exchange_id":Uuid::from_u128(u128::from(seq)+100),"effect_index":2,
            "process_epoch":Uuid::from_u128(20),"phase":"runtime","started_at":at,
            "semantic_required":true,"observed_case":case(),"admitted_case":owner,
            "matched_rule_id":null,"matched_rule_ids":[],
            "attribution":owner.map(|id|json!({"kind":"case","origin_case_id":id}))
                .unwrap_or_else(||json!({"kind":"unattributed","reason":"outside_admission"})),
            "protocol_ref":{"protocol":"mysql","connection_id":connection,"sequence":seq}}
    })
}

fn frames() -> Vec<Frame> {
    let now = Utc::now();
    let windows = BTreeMap::from([(
        case(),
        (
            now - chrono::Duration::seconds(10),
            now + chrono::Duration::seconds(10),
        ),
    )]);
    [
        (1, Some(case()), 0, 1),
        (2, Some(case()), 1, 1),
        (3, None, 1, 0),
        (4, None, 0, 0),
    ]
    .into_iter()
    .map(|(seq, owner, before, after)| {
        Frame::read(&event(seq, owner, before, after), owner, &windows)
            .unwrap()
            .unwrap()
    })
    .collect()
}

#[test]
fn complete_single_case_transaction_owns_end_and_one_idle_cleanup() {
    let entries = frames();
    let expected = BTreeMap::from([
        (entries[2].capture.exchange_id, case()),
        (entries[3].capture.exchange_id, case()),
    ]);
    assert_eq!(prove(entries), expected);
}

#[test]
fn unknown_start_and_unknown_or_mixed_members_do_not_establish_an_owner() {
    let mut entries = frames();
    entries[0].before = 1;
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    entries[1].member_owner = None;
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    entries[1].member_owner = Some(Uuid::from_u128(2));
    assert!(prove(entries).is_empty());
}

#[test]
fn wire_gaps_resource_changes_and_epoch_changes_invalidate_the_transaction() {
    let mut entries = frames();
    entries[2].sequence = 5;
    entries[3].sequence = 6;
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    entries[2].resource = json!(["other", 3306, "app", "app"]);
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    entries[2].capture.process_epoch = Uuid::from_u128(21);
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    entries[2].before = 3;
    assert!(prove(entries).is_empty());
}

#[test]
fn failed_or_unobserved_end_does_not_anchor_idle_cleanup() {
    let mut entries = frames();
    entries[2].rollback = false;
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    entries[2].capture.observed_case = Some(Uuid::from_u128(2));
    assert!(prove(entries).is_empty());
}

#[test]
fn duplicate_wire_identity_is_ambiguous_and_idle_cleanup_is_not_unbounded() {
    let mut entries = frames();
    let duplicate = Frame::read(&event(2, Some(case()), 1, 1), None, &BTreeMap::new())
        .unwrap()
        .unwrap();
    entries.push(duplicate);
    assert!(prove(entries).is_empty());
    let mut entries = frames();
    let extra = Frame::read(&event(5, None, 0, 0), None, &BTreeMap::new())
        .unwrap()
        .unwrap();
    let id = extra.capture.exchange_id;
    entries.push(extra);
    let owners = prove(entries);
    assert_eq!(owners.len(), 2);
    assert!(!owners.contains_key(&id));
}

#[test]
fn case_members_require_original_admission_and_a_complete_primary_window() {
    let e = event(1, Some(case()), 0, 1);
    let now = Utc::now();
    let before = BTreeMap::from([(
        case(),
        (
            now - chrono::Duration::seconds(20),
            now - chrono::Duration::seconds(10),
        ),
    )]);
    assert!(
        Frame::read(&e, Some(case()), &before)
            .unwrap()
            .unwrap()
            .member_owner
            .is_none()
    );
    assert!(
        Frame::read(&e, Some(Uuid::from_u128(2)), &BTreeMap::new())
            .unwrap()
            .unwrap()
            .member_owner
            .is_none()
    );
    let mut invalid = e;
    invalid["capture"]["admitted_case"] = Value::Null;
    assert!(
        Frame::read(&invalid, Some(case()), &BTreeMap::new())
            .unwrap()
            .unwrap()
            .captured_owner
            .is_none()
    );
}

#[test]
fn cleanup_requires_a_complete_plain_zero_effect_rollback() {
    for (pointer, value) in [
        ("/sql", json!("ROLLBACK TO SAVEPOINT s")),
        ("/response/affected_rows", json!(1)),
        ("/response/error_code", json!(1)),
        ("/response/rows_truncated", json!(true)),
        ("/response/rows", json!([[1]])),
        ("/response/server_status", json!(1)),
        ("/params", json!("unknown")),
        ("/parse_warnings", json!(["incomplete"])),
    ] {
        let mut e = event(3, None, 1, 0);
        *e.pointer_mut(pointer).unwrap() = value;
        assert!(
            !Frame::read(&e, None, &BTreeMap::new())
                .unwrap()
                .unwrap()
                .candidate(),
            "{pointer}"
        );
    }
}
