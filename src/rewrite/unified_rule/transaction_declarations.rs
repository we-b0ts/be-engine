//! Full policy declaration proposals retain their graph and prove both surfaces.
use super::*;
use crate::{
    policy::{Resource, Slot, Surface, compile_policy, parse_policy, render_policy},
    policy_evidence::{
        ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
        WitnessStore,
    },
};
use std::collections::{BTreeMap, BTreeSet};

fn declaration(delivery: bool) -> serde_json::Value {
    let mut declaration = json!({"format":"traffic-policy/v2","source_revision":"source",
        "resources":{"cache":{
            "protocol":"redis","endpoint":"cache.test:6379","database":0,
            "proof":{"source":"cache.py:write,read","fact":"Stored event times follow the request clock; member order has no meaning and other fields remain exact"},
            "keys":[{"key":{"prefix":"session:"},"container":"string",
                "value":{"codec":"json","fields":{
                    "/at":{"relative_time":"unix_seconds","proof":{"fact":"Source generates event time from the current request"}},
                    "/members":"unordered"}}}]}},
        "responses":{"result":{"api":"GET /api",
            "proof":{"source":"api.py:members","fact":"Source returns member sets without observing order"},
            "body":{"codec":"json","fields":{"/members":"unordered"}}}},
        "rules":[]});
    if delivery {
        declaration["resources"]["cache"]["keys"][0]["value"]["delivery"] =
            json!({"rebase_time":["/at"]});
    }
    declaration
}

fn fixture() -> Fixture {
    Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
        fs::write(
            root.join(".traffic-e2e/policy.yaml"),
            "format: traffic-policy/v2\nsource_revision: source\nrules: []\n",
        )
        .unwrap();
        vec![]
    })
}

fn stored(at: i64, reversed: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({"at":at,"members":if reversed {[2,1]}else{[1,2]},"stable":"exact"}))
        .unwrap()
}

fn bulk(payload: &[u8]) -> Vec<u8> {
    let mut result = format!("$000{}\r\n", payload.len()).into_bytes();
    result.extend_from_slice(payload);
    result.extend_from_slice(b"\r\n");
    result
}

fn redis_event(
    command: &str,
    sequence: usize,
    args: &[Vec<u8>],
    response: &[u8],
) -> serde_json::Value {
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":sequence,
        "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,
        "database":0,"command":command,"args":args.iter().map(|arg|raw_body(arg)).collect::<Vec<_>>(),
        "response":raw_body(response),"outcome":"response","replay_safe":true})
}

/// Publish real, sealed evidence without assigning the declaration a command.
fn install(fixture: &Fixture, observations: &[(serde_json::Value, Surface, Vec<u8>)]) {
    install_with_read_completion(fixture, observations, None, false, false)
}

fn install_with_read_completion(
    fixture: &Fixture,
    observations: &[(serde_json::Value, Surface, Vec<u8>)],
    completion: Option<chrono::DateTime<chrono::Utc>>,
    completed_inputs: bool,
    separate_read_request: bool,
) {
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
    let mut seen = BTreeSet::new();
    fs::write(
        case.join("dependencies.jsonl"),
        observations
            .iter()
            .filter(|(event, _, _)| seen.insert(event.to_string()))
            .map(|(event, _, _)| format!("{event}\n"))
            .collect::<String>(),
    )
    .unwrap();
    crate::platform::encryption_key::load_or_create(fixture.root()).unwrap();
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    report["session_id"] = json!(session);
    let store = WitnessStore::new_bound(
        fixture.paths.replay.parent().unwrap(),
        &session,
        report["replay_policy"]["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    let source_time = "2026-10-16T00:00:00Z".parse().unwrap();
    let target_time = "2026-10-16T00:01:00Z".parse().unwrap();
    let pair = ClockPair {
        source: Some(source_time),
        target: Some(target_time),
    };
    let resource: Resource = serde_json::from_value(
        json!({"protocol":"redis","endpoint":"cache.test:6379","database":0}),
    )
    .unwrap();
    let mut observation_ids = BTreeMap::new();
    for (event, surface, target) in observations {
        let mut observation_id = observation_ids
            .entry(event.to_string())
            .or_insert_with(|| uuid::Uuid::new_v4().to_string())
            .clone();
        if separate_read_request
            && *surface == Surface::DependencyRequest
            && event["command"] == "GET"
        {
            observation_id = uuid::Uuid::new_v4().to_string();
        }
        let source_completed = event["timestamp"].as_str().unwrap().parse().unwrap();
        let dependency_pair = ClockPair {
            source: Some(source_completed),
            target: pair.target,
        };
        let source = crate::rewrite::unified_rule::preflight::dependency::source_witness(
            *surface, event, &case,
        )
        .unwrap();
        store
            .record_observation(
                WitnessMetadata {
                    surface: *surface,
                    source_role: if *surface == Surface::DependencyRequest {
                        SourceRole::DependencyRequest
                    } else {
                        SourceRole::DependencyResponse
                    },
                    target_role: if *surface == Surface::DependencyRequest {
                        TargetRole::IndependentTargetObservation
                    } else if completed_inputs {
                        TargetRole::DeliveredInput
                    } else {
                        TargetRole::DerivedDelivery
                    },
                    source: SourceIdentity {
                        case_id: "case-1".into(),
                        exchange_id: None,
                        connection_id: event["connection_id"].as_str().map(str::to_owned),
                        sequence: event["sequence"].as_u64(),
                    },
                    resource: Some(resource.clone()),
                    operation: event["command"].as_str().unwrap().into(),
                    slot: Slot::Value,
                    clocks: WitnessClocks {
                        case: pair.clone(),
                        dependency: dependency_pair.clone(),
                        delivery: if *surface == Surface::DependencyResponse
                            && event["command"] == "GET"
                        {
                            ClockPair {
                                source: Some(source_completed),
                                target: completion.or(pair.target),
                            }
                        } else {
                            dependency_pair.clone()
                        },
                    },
                },
                &case,
                &source,
                Some(target),
                Some(&observation_id),
            )
            .unwrap();
    }
    report["cases"][0]["target_request_started_at"] = json!(target_time);
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
}

fn observations(reads: bool) -> Vec<(serde_json::Value, Surface, Vec<u8>)> {
    let at = "2026-10-16T00:00:10Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap()
        .timestamp();
    let before = stored(at, false);
    let after = stored(at + 60, true);
    let mut result = Vec::new();
    for (index, command) in ["SET", "SETEX", "MSET"].into_iter().enumerate() {
        let mut source_args = vec![b"session:one".to_vec()];
        if command == "SETEX" {
            source_args.push(b"30".to_vec());
        }
        source_args.push(before.clone());
        if command == "MSET" {
            source_args.extend([b"outside".to_vec(), b"opaque".to_vec()]);
        }
        let mut target_args = source_args.clone();
        target_args[if command == "SETEX" { 2 } else { 1 }] = after.clone();
        result.push((
            redis_event(command, index + 1, &source_args, b"+OK\r\n"),
            Surface::DependencyRequest,
            serde_json::to_vec(&target_args).unwrap(),
        ));
    }
    if reads {
        let delivered = stored(at + 60, false);
        for (index, command) in ["GET", "MGET"].into_iter().enumerate() {
            let mut source = bulk(&before);
            let mut target = bulk(&delivered);
            let mut args = vec![b"session:one".to_vec()];
            if command == "MGET" {
                source = [b"*2\r\n".as_slice(), source.as_slice(), b"$-1\r\n"].concat();
                target = [b"*2\r\n".as_slice(), target.as_slice(), b"$-1\r\n"].concat();
                args.push(b"outside".to_vec());
            }
            result.push((
                redis_event(command, index + 4, &args, &source),
                Surface::DependencyResponse,
                target,
            ));
        }
    }
    result
}

#[test]
fn schema_only_plan_apply_retains_resource_graph_proofs_and_command_independence() {
    let fixture = fixture();
    let proposed = declaration(true);
    write(&fixture.proposal, proposed.clone());
    install(&fixture, &observations(true));
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    let preflight = &planned.traffic_e2e_report["preflight"];
    assert!(
        preflight["independent_target_validations"]
            .as_u64()
            .unwrap()
            >= 3
    );
    assert_eq!(preflight["derived_delivery_validations"], 2);
    let document = parse_policy(&proposed.to_string()).unwrap();
    let compiled = compile_policy(&document).unwrap();
    assert_eq!(compiled.rules.len(), 3);
    let ids = compiled
        .rules
        .iter()
        .map(|rule| rule.rule.id.as_str())
        .collect::<BTreeSet<_>>();
    let expanded = planned.traffic_e2e_report["expanded_rules"]
        .as_array()
        .unwrap();
    assert_eq!(
        expanded
            .iter()
            .map(|rule| rule["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        ids
    );
    let dependency = compiled
        .rules
        .iter()
        .filter(|rule| rule.rule.surface != Surface::ApiResponse)
        .collect::<Vec<_>>();
    assert!(
        dependency
            .iter()
            .all(|rule| rule.rule.selector.operation.is_none())
    );
    assert_eq!(
        compiled.origins[&dependency[0].rule.id],
        compiled.origins[&dependency[1].rule.id]
    );
    assert_eq!(
        dependency[0].field_proofs["/at"].source,
        "cache.py:write,read @ source"
    );
    assert_eq!(
        dependency[0].field_proofs["/at"].fact,
        "Source generates event time from the current request"
    );
    assert_eq!(
        preflight["rules"][&dependency[0].rule.id].as_u64().unwrap()
            + preflight["rules"][&dependency[1].rule.id].as_u64().unwrap(),
        5
    );
    assert_eq!(planned.traffic_e2e_report["verified"], false);
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    assert_eq!(
        applied.traffic_e2e_report["expanded_rules"],
        planned.traffic_e2e_report["expanded_rules"]
    );
    let text = fs::read_to_string(fixture.policy()).unwrap();
    assert!(!text.contains(" @ source"));
    let reparsed = parse_policy(&text).unwrap();
    assert_eq!(reparsed, document);
    assert!(reparsed.rules.is_empty());
    assert_eq!(
        parse_policy(&render_policy(&reparsed).unwrap()).unwrap(),
        reparsed
    );
    assert_eq!(compile_policy(&reparsed).unwrap(), compiled);
    assert!(fixture.state().rule_replay_pending);
}

#[test]
fn field_declarations_require_source_evidence_and_explicit_delivery_requires_a_read() {
    for writes in [false, true] {
        let fixture = fixture();
        write(&fixture.proposal, declaration(true));
        if writes {
            install(&fixture, &observations(false));
        }
        let active = fs::read(fixture.policy()).unwrap();
        fixture.confirm();
        let error = fixture.plan().unwrap_err();
        assert!(
            format!("{error:#}").contains("selects no complete Source witness"),
            "{error:#}"
        );
        assert_eq!(fs::read(fixture.policy()).unwrap(), active);
        assert!(!fixture.state().rule_replay_pending);
    }
}

#[test]
fn comparison_only_read_write_peers_share_source_schema_evidence() {
    let fixture = fixture();
    write(&fixture.proposal, declaration(false));
    install(&fixture, &observations(false));
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["preflight"]["derived_delivery_validations"],
        0
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    assert!(
        parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap()
            .rules
            .is_empty()
    );
}

#[test]
fn comparison_only_reads_do_not_claim_derived_delivery_as_target_proof() {
    let fixture = fixture();
    write(&fixture.proposal, declaration(false));
    install(&fixture, &observations(true));
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
    let preflight = &planned.traffic_e2e_report["preflight"];
    assert_eq!(preflight["derived_delivery_validations"], 0);
    assert_eq!(preflight["missing_target_witnesses"], 2);
    assert!(
        preflight["independent_target_validations"]
            .as_u64()
            .unwrap()
            >= 3
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
}

#[test]
fn independent_identity_payloads_leave_case_graph_pending_and_keep_strict_remainder() {
    const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
    const TARGET: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER_TARGET: &str = "33333333-3333-4333-8333-333333333333";
    for conditional in [false, true] {
        for scenario in [
            "consistent",
            "split-across-observations",
            "changed-business",
        ] {
            let fixture = fixture();
            let mut proposed = declaration(false);
            let identity = json!({"kind":"identity","binding":"stored-task","format":"uuid"});
            proposed["resources"]["cache"]["keys"][0]["value"]["fields"] = json!({
                "/id": if conditional {
                    json!({"kind":"conditional","when":{"relative_pointer":"../kind","equals":"generated"},"contract":identity})
                } else { identity }
            });
            proposed["resources"]["cache"]["proof"] = json!({
                "source":"cache.py:write,read",
                "fact":"Source generates task UUIDs and repeats their identities at these stored locations; business fields remain exact"
            });
            write(&fixture.proposal, proposed.clone());
            let observations = (0..2)
                .map(|index| {
                    let source = serde_json::to_vec(&json!({
                        "id":SOURCE,"kind":"generated","business":"exact"
                    }))
                    .unwrap();
                    let target = serde_json::to_vec(&json!({
                        "id":if index == 1 && scenario == "split-across-observations" {OTHER_TARGET} else {TARGET},
                        "kind":"generated",
                        "business":if index == 1 && scenario == "changed-business" {"changed"} else {"exact"}
                    }))
                    .unwrap();
                    let args = vec![b"session:one".to_vec(), source];
                    (
                        redis_event("SET", index + 1, &args, b"+OK\r\n"),
                        Surface::DependencyRequest,
                        serde_json::to_vec(&vec![b"session:one".to_vec(), target]).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            install(&fixture, &observations);
            fixture.confirm();
            let planned = fixture.plan();
            if scenario == "changed-business" {
                assert!(
                    planned.is_err(),
                    "an identity Replay obligation cannot hide the remainder"
                );
                continue;
            }
            // Protected candidate edges do not prove which pairs were accepted.
            // A locally valid pair must not make the case-wide graph verified,
            // including when different observations propose incompatible maps.
            let planned = planned.unwrap();
            let compiled = compile_policy(&parse_policy(&proposed.to_string()).unwrap()).unwrap();
            let identity_ids = compiled
                .rules
                .iter()
                .filter(|rule| rule.rule.surface != Surface::ApiResponse)
                .map(|rule| rule.rule.id.clone())
                .collect::<BTreeSet<_>>();
            let preflight = &planned.traffic_e2e_report["preflight"];
            let obligations = serde_json::from_value::<BTreeSet<String>>(
                preflight["stateful_target_obligations"].clone(),
            )
            .unwrap();
            assert_eq!(obligations, identity_ids);
            assert!(
                preflight["independent_target_validations"]
                    .as_u64()
                    .unwrap()
                    >= 2
            );
            assert_eq!(planned.traffic_e2e_report["status"], "planned_needs_replay");
            assert_eq!(planned.traffic_e2e_report["verified"], false);
            let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
            assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
            assert_eq!(
                applied.traffic_e2e_report["status"],
                "applied_pending_replay"
            );
            assert!(fixture.state().rule_replay_pending);
        }
    }
}

#[test]
fn historical_read_copy_and_a_fresh_time_compose_in_schema_only_plan_apply() {
    for mode in [
        "valid",
        "future_delivery",
        "missing_request",
        "fresh_time_bug",
        "future_source_read",
        "other_target_key",
        "future_source_timestamp",
        "unsafe_read",
        "render_only_input",
        "global_read",
        "snapshot_read",
        "terminated_read",
        "unpaired_request",
    ] {
        let fixture = fixture();
        let mut policy = declaration(false);
        policy["resources"]["cache"]["keys"][0]["value"]["fields"]["/updated"] =
            json!({"relative_time":"unix_seconds"});
        write(&fixture.proposal, policy);
        let now = "2026-10-16T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            .timestamp();
        let old = json!({"at":1000,"updated":500,"members":[1,2],"stable":"exact"});
        let source_read = serde_json::to_vec(&old).unwrap();
        let mut changed = old.clone();
        changed["updated"] = json!(now);
        let source_write = serde_json::to_vec(&changed).unwrap();
        let target_write = serde_json::to_vec(&json!({"at":1000,"updated":now + if mode == "fresh_time_bug" {0}else{60},"members":[2,1],"stable":"exact"})).unwrap();
        let read_args = vec![b"session:one".to_vec()];
        let mut read = redis_event("GET", 1, &read_args, &bulk(&source_read));
        if mode == "future_source_timestamp" {
            read["timestamp"] = json!("2026-10-16T00:00:01Z");
        }
        if mode == "unsafe_read" {
            read["replay_safe"] = json!(false);
        }
        if mode == "global_read" {
            read["global_dependency_reason"] = json!("shared");
        }
        if mode == "snapshot_read" {
            read["cache_snapshot_hit"] = json!(true);
        }
        if mode == "terminated_read" {
            read["outcome"] = json!({"terminated": "read_timeout"});
        }
        let source_args = vec![b"session:one".to_vec(), source_write];
        let mut target_args = source_args.clone();
        target_args[1] = target_write;
        let write_event = redis_event("MSET", 2, &source_args, b"+OK\r\n");
        let mut observations = vec![
            (
                read.clone(),
                Surface::DependencyResponse,
                bulk(&source_read),
            ),
            (
                write_event,
                Surface::DependencyRequest,
                serde_json::to_vec(&target_args).unwrap(),
            ),
        ];
        if mode == "future_source_read" {
            observations.swap(0, 1);
        }
        if mode != "missing_request" {
            let delivered_args = if mode == "other_target_key" {
                vec![b"session:other".to_vec()]
            } else {
                read_args
            };
            observations.push((
                read,
                Surface::DependencyRequest,
                serde_json::to_vec(&delivered_args).unwrap(),
            ));
        }
        let completion = if mode == "future_delivery" {
            Some("2026-10-16T00:01:01Z".parse().unwrap())
        } else {
            None
        };
        install_with_read_completion(
            &fixture,
            &observations,
            completion,
            mode != "render_only_input",
            mode == "unpaired_request",
        );
        fixture.confirm();
        let planned = fixture.plan();
        if mode != "valid" {
            assert!(
                planned.is_err(),
                "{mode} borrowed an unproven input or relaxed fresh generation"
            );
            continue;
        }
        let planned = planned.unwrap();
        assert!(
            planned.traffic_e2e_report["preflight"]["independent_target_validations"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert_eq!(
            planned.traffic_e2e_report["preflight"]["derived_delivery_validations"],
            0
        );
        assert_eq!(
            apply_rewrite_rule(fixture.context(), &planned.plan_id)
                .unwrap()
                .traffic_e2e_report["status"],
            "applied_pending_replay"
        );
    }
}
