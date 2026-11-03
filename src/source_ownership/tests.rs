//! Focused Source ownership regression fixtures.
use super::*;
use serde_json::json;

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}
fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap()
}
fn resource(protocol: &str) -> Value {
    if protocol == "mysql" {
        json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"app"})
    } else {
        json!({"protocol":"redis","endpoint":"cache.test:6379","database":0,"username":"default"})
    }
}
fn rules() -> BTreeMap<String, crate::policy::AsyncApiRules> {
    serde_json::from_value(json!({"POST /jobs":[{
        "when":{},"when_response":{"/status":"in_progress"},
        "end":[{"redis":{"operation":"DEL","key":"cancel:*"}}],
        "ownership":{
            "origin":{"resource":resource("mysql"),"tables":["work_items"],"row_match":{"role":"assistant"},"bindings":{"subtask":"id","task":"task_id"}},
            "requests":[
                {"protocol":"redis","resource":resource("redis"),"operation":"GET","arguments":[{"identity":"subtask","prefix":"work:item:"}]},
                {"protocol":"redis","resource":resource("redis"),"operation":"PUBLISH","arguments":["events",{"json":{"/type":{"literal":"done"},"/data/task_id":{"identity":"task"}}}]},
                {"protocol":"redis","resource":resource("redis"),"operation":"EVALSHA","arguments":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","0",{"identity":"subtask"}],"script_exists_prelude":true},
                {"protocol":"mysql","resource":resource("mysql"),"sql":"UPDATE {{table}} SET state=? WHERE id=?","tables":["work_items"],"bindings":{"1":"subtask"}},
                {"protocol":"mysql","resource":resource("mysql"),"sql":"SELECT key_name FROM configs WHERE enabled=?","tables":["configs"],"transaction_member":true}
            ]
        }
    }]})).unwrap()
}
fn input(case: u128, seconds: i64, request: Value) -> CaseFacts {
    CaseFacts {
        case_id: id(case),
        method: "POST".into(),
        uri: "/jobs".into(),
        request: Some(request),
        request_unavailable: false,
        response: Some(json!({"status":"in_progress"})),
        started_at: at(seconds),
    }
}

fn inputs() -> Vec<CaseFacts> {
    vec![input(10, 0, json!({})), input(20, 10, json!({"other":202}))]
}
fn capture(event: u128, case: u128, seconds: i64) -> Value {
    json!({"exchange_id":id(event),"process_epoch":id(100),"phase":"runtime","observed_case":id(case),"admitted_case":id(case),"started_at":at(seconds),"semantic_required":true,"attribution":{"kind":"case","origin_case_id":id(case)}})
}
fn mysql_event(
    event: u128,
    case: u128,
    sequence: u64,
    before: u16,
    after: u16,
    sql: &str,
) -> Value {
    let mut captured = capture(
        event,
        case,
        if case == 20 {
            10 + sequence as i64
        } else {
            sequence as i64
        },
    );
    captured["protocol_ref"] =
        json!({"protocol":"mysql","connection_id":id(500),"sequence":sequence});
    let affected = u64::from(!matches!(sql, "COMMIT" | "ROLLBACK" | "BEGIN"));
    json!({"event_type":"mysql_exchange","capture":captured,"connection_id":id(500),"query_sequence":sequence,"target_host":"db.test","target_port":3306,"database":"app","username":"app","command":"COM_QUERY","sql":sql,"outcome":"response","parse_warnings":[],"server_status_before":before,"response":{"status":"ok","affected_rows":affected,"last_insert_id":0,"row_count":0,"server_status":after,"rows_truncated":false,"rows":[],"columns":[]}})
}
fn origin(case: u128, subtask: u64, task: u64) -> Vec<Value> {
    vec![
        mysql_event(
            1,
            case,
            1,
            0,
            1,
            &format!(
                "INSERT INTO work_items (id,task_id,role) VALUES ({subtask},{task},'assistant')"
            ),
        ),
        mysql_event(2, case, 2, 1, 0, "COMMIT"),
    ]
}
fn redis_event(event: u128, case: u128, sequence: u64, operation: &str, args: Vec<Value>) -> Value {
    let args = args
        .iter()
        .map(|value| json!({"encoding":"utf8","data":value.as_str().unwrap(),"truncated":false}))
        .collect::<Vec<_>>();
    let mut captured = capture(event, case, 10 + sequence as i64);
    captured["protocol_ref"] =
        json!({"protocol":"redis","connection_id":id(600),"sequence":sequence});
    json!({"event_type":"redis_exchange","capture":captured,"connection_id":id(600),"sequence":sequence,"target_host":"cache.test","target_port":6379,"database":0,"username":"default","command":operation,"args":args,"outcome":"response","response_kind":"bulk_string","response":{"encoding":"utf8","data":"payload never used","truncated":false},"parse_warnings":[],"replay_safe":true})
}

#[test]
fn unique_committed_origin_claims_unowned_and_next_case_requests() {
    let mut events = origin(10, 11, 101);
    let mut unowned = redis_event(3, 10, 1, "GET", vec![json!("work:item:11")]);
    unowned["capture"]["admitted_case"] = Value::Null;
    unowned["capture"]["attribution"] = json!({"kind":"unattributed","reason":"outside_admission"});
    events.push(unowned);
    events.push(redis_event(4, 20, 2, "GET", vec![json!("work:item:11")]));
    let outcome = classify(
        &rules(),
        &[input(10, 0, json!({})), input(20, 10, json!({"other":202}))],
        &events,
    )
    .unwrap();
    assert_eq!(outcome.decisions.len(), 2);
    assert!(
        outcome
            .decisions
            .values()
            .all(|assignment| assignment.case_id == id(10))
    );
}

#[test]
fn absent_commit_and_rollback_creation_do_not_prove_an_origin() {
    for completion in [None, Some("ROLLBACK")] {
        let mut events = origin(10, 11, 101);
        if let Some(completion) = completion {
            events[1]["sql"] = json!(completion);
        } else {
            events.remove(1);
        }
        events.push(redis_event(3, 20, 1, "GET", vec![json!("work:item:11")]));
        assert!(
            classify(&rules(), &inputs(), &events)
                .unwrap()
                .decisions
                .is_empty()
        );
    }
}

#[test]
fn duplicate_origins_and_later_same_resource_ingress_remain_ambiguous() {
    let mut events = origin(10, 11, 101);
    let mut other = origin(20, 11, 101);
    for event in &mut other {
        event["connection_id"] = json!(id(501));
        event["capture"]["protocol_ref"]["connection_id"] = json!(id(501));
        event["capture"]["exchange_id"] =
            json!(id(1000 + event["query_sequence"].as_u64().unwrap() as u128));
        event["capture"]["started_at"] = json!(at(12));
    }
    events.extend(other);
    events.push(redis_event(3, 30, 5, "GET", vec![json!("work:item:11")]));
    let outcome = classify(
        &rules(),
        &[
            input(10, 0, json!({})),
            input(20, 10, json!({})),
            input(30, 14, json!({})),
        ],
        &events,
    )
    .unwrap();
    assert!(outcome.decisions.is_empty());
    assert!(
        outcome
            .problems
            .iter()
            .any(|problem| problem.reason == "ambiguous_origin")
    );
    let mut events = origin(10, 11, 101);
    events.push(redis_event(3, 20, 2, "GET", vec![json!("work:item:11")]));
    assert!(
        classify(
            &rules(),
            &[
                input(10, 0, json!({})),
                input(20, 10, json!({"subtask_id":11}))
            ],
            &events
        )
        .unwrap()
        .decisions
        .is_empty()
    );
}

#[test]
fn complete_transaction_inherits_only_whitelisted_id_free_members() {
    let mut events = origin(10, 11, 101);
    events.extend([
        mysql_event(
            3,
            20,
            3,
            0,
            1,
            "SELECT key_name FROM configs WHERE enabled=1",
        ),
        mysql_event(
            4,
            20,
            4,
            1,
            1,
            "UPDATE work_items SET state='FAILED' WHERE id=11",
        ),
        mysql_event(5, 20, 5, 1, 0, "COMMIT"),
        mysql_event(6, 20, 6, 0, 0, "ROLLBACK"),
    ]);
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert_eq!(
        outcome.decisions.keys().copied().collect::<Vec<_>>(),
        vec![id(3), id(4), id(5), id(6)]
    );
    events[2]["sql"] = json!("SELECT secret FROM unrelated WHERE enabled=1");
    assert!(
        classify(&rules(), &inputs(), &events)
            .unwrap()
            .decisions
            .is_empty()
    );
}

#[test]
fn transaction_gap_mixed_identity_and_failed_write_never_inherit() {
    for mutation in ["gap", "foreign", "error", "rollback"] {
        let mut events = origin(10, 11, 101);
        events.extend([
            mysql_event(
                3,
                20,
                3,
                0,
                1,
                "UPDATE work_items SET state='FAILED' WHERE id=11",
            ),
            mysql_event(4, 20, 4, 1, 0, "COMMIT"),
        ]);
        match mutation {
            "gap" => events[3]["query_sequence"] = json!(5),
            "foreign" => events.insert(
                3,
                mysql_event(
                    5,
                    20,
                    4,
                    1,
                    1,
                    "UPDATE work_items SET state='FAILED' WHERE id=999",
                ),
            ),
            "error" => events[2]["response"]["error_code"] = json!(1234),
            "rollback" => events[3]["sql"] = json!("ROLLBACK"),
            _ => unreachable!(),
        }
        assert!(
            classify(&rules(), &inputs(), &events)
                .unwrap()
                .decisions
                .is_empty(),
            "{mutation}"
        );
    }
}

#[test]
fn script_prelude_requires_immediate_same_connection_invocation() {
    let mut events = origin(10, 11, 101);
    events.push(redis_event(
        3,
        20,
        1,
        "SCRIPT",
        vec![
            json!("EXISTS"),
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ],
    ));
    events.push(redis_event(
        4,
        20,
        2,
        "EVALSHA",
        vec![
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            json!("0"),
            json!("11"),
        ],
    ));
    assert_eq!(
        classify(&rules(), &inputs(), &events)
            .unwrap()
            .decisions
            .len(),
        2
    );
    events[3]["sequence"] = json!(3);
    events[3]["capture"]["protocol_ref"]["sequence"] = json!(3);
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert_eq!(outcome.decisions.len(), 1);
    assert!(outcome.decisions.contains_key(&id(4)));
}

#[test]
fn publish_requires_literal_json_discriminator_and_bound_identity() {
    let mut events = origin(10, 11, 101);
    events.push(redis_event(
        3,
        20,
        1,
        "PUBLISH",
        vec![
            json!("events"),
            json!(r#"{"type":"done","data":{"task_id":101,"private":"not surfaced"}}"#),
        ],
    ));
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert_eq!(outcome.decisions.len(), 1);
    assert!(
        !serde_json::to_string(&outcome)
            .unwrap()
            .contains("not surfaced")
    );
    events[2]["args"][1]["data"] = json!(r#"{"type":"other","data":{"task_id":101}}"#);
    assert!(
        classify(&rules(), &inputs(), &events)
            .unwrap()
            .decisions
            .is_empty()
    );
}

#[test]
fn request_projection_discards_rows_and_preserves_incomplete_capture() {
    let mut events = origin(10, 11, 101);
    events[0]["response"]["rows"] =
        json!([[{"raw":{"truncated":true},"value":"must not survive"}]]);
    let projected = request_view(&events[0], &rules()).unwrap();
    assert!(projected["response"]["rows"].is_null());
    assert_eq!(projected["_capture_complete"], false);
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("must not survive")
    );
}

#[test]
fn native_epoch_and_request_time_are_independent_origin_guards() {
    for mutation in ["epoch", "time", "truncated"] {
        let mut events = origin(10, 11, 101);
        events.push(redis_event(3, 20, 1, "GET", vec![json!("work:item:11")]));
        match mutation {
            "epoch" => events[2]["capture"]["process_epoch"] = json!(id(101)),
            "time" => events[2]["capture"]["started_at"] = json!(at(0)),
            "truncated" => events[2]["args"][0]["truncated"] = json!(true),
            _ => unreachable!(),
        }
        assert!(
            classify(&rules(), &inputs(), &events)
                .unwrap()
                .decisions
                .is_empty(),
            "{mutation}"
        );
    }
}

#[test]
fn schema_rejects_implicit_id_free_selection_and_unknown_bindings() {
    let rules = rules();
    let ownership = rules["POST /jobs"][0].ownership.as_ref().unwrap();
    assert!(crate::policy::validate_async_ownership(ownership).is_ok());
    let mut changed = serde_json::to_value(ownership).unwrap();
    changed["requests"][3]["bindings"] = json!({});
    assert!(
        crate::policy::validate_async_ownership(&serde_json::from_value(changed).unwrap()).is_err()
    );
}

#[test]
fn encoded_and_uninspectable_later_inputs_keep_full_unresolved_identity() {
    let mut events = origin(10, 11, 101);
    events.push(redis_event(3, 20, 2, "GET", vec![json!("work:item:11")]));
    let mut facts = inputs();
    facts[1].uri = "/jobs?subtask_id=%31%31".into();
    let outcome = classify(&rules(), &facts, &events).unwrap();
    assert!(outcome.decisions.is_empty());
    assert_eq!(outcome.unresolved, BTreeSet::from([id(3)]));
    facts[1].uri = "/jobs".into();
    facts[1].request = None;
    facts[1].request_unavailable = true;
    assert_eq!(
        classify(&rules(), &facts, &events).unwrap().unresolved,
        BTreeSet::from([id(3)])
    );
    assert!(!request_unavailable(
        &json!({"body":{"encoding":"utf8","data":"","truncated":false}})
    ));
    assert!(request_unavailable(
        &json!({"body":{"encoding":"utf8","data":"not JSON","truncated":false}})
    ));
    assert!(request_unavailable(
        &json!({"body":{"encoding":"utf8","data":"","truncated":true}})
    ));
}

#[test]
fn bounded_diagnostics_do_not_drop_authoritative_unresolved_occurrences() {
    let mut events = origin(10, 11, 101);
    for index in 0..300 {
        events.push(redis_event(
            1000 + index,
            20,
            1 + index as u64,
            "GET",
            vec![json!("work:item:11")],
        ));
    }
    let mut facts = inputs();
    facts[1].request_unavailable = true;
    let outcome = classify(&rules(), &facts, &events).unwrap();
    assert!(outcome.decisions.is_empty());
    assert_eq!(outcome.problems.len(), 256);
    assert_eq!(outcome.unresolved.len(), 300);
}

#[test]
fn idle_rollback_requires_zero_effect_and_ping_is_a_native_observation() {
    let mut events = origin(10, 11, 101);
    events.extend([
        mysql_event(
            3,
            20,
            3,
            0,
            1,
            "SELECT key_name FROM configs WHERE enabled=1",
        ),
        mysql_event(4, 20, 4, 1, 1, "ping"),
        mysql_event(
            5,
            20,
            5,
            1,
            1,
            "UPDATE work_items SET state='FAILED' WHERE id=11",
        ),
        mysql_event(6, 20, 6, 1, 0, "COMMIT"),
        mysql_event(7, 20, 7, 0, 0, "ROLLBACK"),
    ]);
    events[3]["command"] = json!("COM_PING");
    events[3]["sql"] = Value::Null;
    events[3]["capture"]["semantic_required"] = json!(false);
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert_eq!(
        outcome.decisions.keys().copied().collect::<Vec<_>>(),
        vec![id(3), id(5), id(6), id(7)]
    );
    events[6]["response"]["affected_rows"] = json!(1);
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert!(!outcome.decisions.contains_key(&id(7)));
}

#[test]
fn malformed_native_origin_identity_cannot_supply_an_ownership_anchor() {
    let mut events = origin(10, 11, 101);
    events.push(redis_event(3, 20, 2, "GET", vec![json!("work:item:11")]));
    events[0]["capture"]["protocol_ref"]["sequence"] = json!(99);
    assert!(
        classify(&rules(), &inputs(), &events)
            .unwrap()
            .decisions
            .is_empty()
    );
}

#[test]
fn non_unique_same_case_creation_is_negative_authority_for_late_dependencies() {
    let mut events = origin(10, 11, 101);
    events.extend([
        mysql_event(
            10,
            10,
            3,
            0,
            1,
            "INSERT INTO work_items (id,task_id,role) VALUES (12,102,'assistant')",
        ),
        mysql_event(11, 10, 4, 1, 0, "COMMIT"),
    ]);
    events.push(redis_event(20, 20, 3, "GET", vec![json!("work:item:11")]));
    events.push(redis_event(21, 20, 4, "GET", vec![json!("work:item:12")]));
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert!(outcome.decisions.is_empty());
    assert_eq!(outcome.unresolved, BTreeSet::from([id(20), id(21)]));
    assert!(!outcome.unresolved.contains(&id(1)) && !outcome.unresolved.contains(&id(10)));
}

#[test]
fn unavailable_execution_has_a_complete_negative_selected_scope() {
    let mut events = origin(10, 11, 101);
    events.extend([
        mysql_event(
            3,
            20,
            3,
            0,
            1,
            "UPDATE work_items SET state='FAILED' WHERE id=11",
        ),
        mysql_event(4, 20, 4, 1, 0, "COMMIT"),
        mysql_event(5, 20, 5, 0, 0, "ROLLBACK"),
    ]);
    events.push(redis_event(
        6,
        20,
        1,
        "SCRIPT",
        vec![
            json!("EXISTS"),
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ],
    ));
    events.push(redis_event(
        7,
        20,
        2,
        "EVALSHA",
        vec![
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            json!("0"),
            json!("11"),
        ],
    ));
    assert_eq!(
        potential_occurrences(&rules(), &events),
        BTreeSet::from([id(3), id(4), id(5), id(6), id(7)])
    );
}

#[test]
fn rollback_to_savepoint_prevents_false_committed_creation_proof() {
    let mut events = vec![
        mysql_event(1, 10, 1, 0, 1, "SAVEPOINT earlier"),
        mysql_event(
            2,
            10,
            2,
            1,
            1,
            "INSERT INTO work_items (id,task_id,role) VALUES (11,101,'assistant')",
        ),
        mysql_event(3, 10, 3, 1, 1, "ROLLBACK TO SAVEPOINT earlier"),
        mysql_event(4, 10, 4, 1, 0, "COMMIT"),
    ];
    events.push(redis_event(5, 20, 2, "GET", vec![json!("work:item:11")]));
    assert!(
        classify(&rules(), &inputs(), &events)
            .unwrap()
            .decisions
            .is_empty()
    );
}

#[test]
fn protected_process_startup_shutdown_and_native_observations_are_out_of_scope() {
    let mut events = origin(10, 11, 101);
    for (index, (phase, kind)) in [
        ("runtime", "process"),
        ("startup", "startup"),
        ("shutdown", "shutdown"),
        ("runtime", "startup"),
        ("runtime", "shutdown"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut redis = redis_event(
            100 + index as u128,
            20,
            index as u64 + 1,
            "GET",
            vec![json!("work:item:11")],
        );
        redis["capture"]["phase"] = json!(phase);
        redis["capture"]["attribution"] = json!({"kind":kind});
        events.push(redis);
        let mut update = mysql_event(
            200 + index as u128 * 2,
            20,
            20 + index as u64 * 2,
            0,
            1,
            "UPDATE work_items SET state='FAILED' WHERE id=11",
        );
        update["capture"]["phase"] = json!(phase);
        update["capture"]["attribution"] = json!({"kind":kind});
        let mut commit = mysql_event(
            201 + index as u128 * 2,
            20,
            21 + index as u64 * 2,
            1,
            0,
            "COMMIT",
        );
        commit["capture"]["phase"] = json!(phase);
        commit["capture"]["attribution"] = json!({"kind":kind});
        events.extend([update, commit]);
    }
    let outcome = classify(&rules(), &inputs(), &events).unwrap();
    assert!(outcome.decisions.is_empty());
    assert!(outcome.unresolved.is_empty());
    assert!(potential_occurrences(&rules(), &events).is_empty());
    let mut nonsemantic = redis_event(999, 20, 20, "GET", vec![json!("work:item:11")]);
    nonsemantic["capture"]["semantic_required"] = json!(false);
    events.push(nonsemantic);
    assert!(
        classify(&rules(), &inputs(), &events)
            .unwrap()
            .unresolved
            .is_empty()
    );
    assert!(potential_occurrences(&rules(), &events).is_empty());
}

#[test]
fn discarded_native_proof_keeps_foreign_selected_occurrences_unresolved() {
    for kind in ["gap", "flags", "unknown", "duplicate"] {
        let mut events = origin(10, 11, 101);
        events.extend([
            mysql_event(
                3,
                20,
                3,
                0,
                1,
                "UPDATE work_items SET state='FAILED' WHERE id=11",
            ),
            mysql_event(4, 20, 4, 1, 0, "COMMIT"),
        ]);
        match kind {
            "gap" => {
                events[3]["query_sequence"] = json!(5);
                events[3]["capture"]["protocol_ref"]["sequence"] = json!(5);
            }
            "flags" => events[3]["server_status_before"] = json!(0),
            "unknown" => events[2]["server_status_before"] = Value::Null,
            "duplicate" => events.push(events[3].clone()),
            _ => unreachable!(),
        }
        let outcome = classify(&rules(), &inputs(), &events).unwrap();
        assert!(!outcome.decisions.contains_key(&id(3)), "{kind}");
        assert!(outcome.unresolved.contains(&id(3)), "{kind}");
    }
}

#[test]
fn script_prelude_needs_its_own_origin_and_scope_guards() {
    let mut events = origin(10, 11, 101);
    events.push(redis_event(
        3,
        20,
        1,
        "SCRIPT",
        vec![
            json!("EXISTS"),
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ],
    ));
    events.push(redis_event(
        4,
        10,
        2,
        "EVALSHA",
        vec![
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            json!("0"),
            json!("11"),
        ],
    ));
    let mut facts = inputs();
    facts[1].request = Some(json!({"subtask":11}));
    let outcome = classify(&rules(), &facts, &events).unwrap();
    assert!(outcome.decisions.contains_key(&id(4)));
    assert!(!outcome.decisions.contains_key(&id(3)));
    assert!(outcome.unresolved.contains(&id(3)));
    events[2]["capture"]["attribution"] = json!({"kind":"process"});
    let outcome = classify(&rules(), &facts, &events).unwrap();
    assert!(outcome.decisions.contains_key(&id(4)));
    assert!(!outcome.unresolved.contains(&id(3)));
}

#[test]
fn prepared_sql_index_preserves_every_positive_and_negative_pair() {
    let rules = rules();
    let selected = rules
        .iter()
        .flat_map(|(api, scenarios)| {
            scenarios
                .iter()
                .enumerate()
                .filter_map(move |(scenario_index, scenario)| {
                    scenario.ownership.as_ref().map(|ownership| Rule {
                        api,
                        scenario_index,
                        ownership,
                        fingerprint: crate::policy::async_rules_fingerprint(scenarios),
                    })
                })
        })
        .collect::<Vec<_>>();
    let mut events = origin(10, 11, 101);
    events.extend([
        mysql_event(
            3,
            20,
            3,
            0,
            1,
            "SELECT key_name FROM configs WHERE enabled=1",
        ),
        mysql_event(
            4,
            20,
            4,
            1,
            1,
            "UPDATE work_items SET state='FAILED' WHERE id=11",
        ),
        mysql_event(5, 20, 5, 1, 0, "COMMIT"),
        mysql_event(
            6,
            20,
            6,
            0,
            1,
            "UPDATE work_items SET state='RUNNING' WHERE id=999",
        ),
        mysql_event(7, 20, 7, 1, 0, "ROLLBACK"),
        mysql_event(8, 20, 8, 0, 2, "SELECT secret FROM unrelated WHERE id=11"),
    ]);
    let index = mysql::prepared::Matches::new(&selected, &events);
    for event in &events {
        for request in selected.iter().flat_map(|rule| &rule.ownership.requests) {
            assert_eq!(
                index.selector(request, event),
                mysql::selector(request, event)
            );
        }
        assert_eq!(index.boundary(event), mysql::boundary(event));
    }
    let (_, row) = index.row(&events[0]).unwrap();
    assert_eq!(
        row.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["id", "role", "task_id"]
    );
}
