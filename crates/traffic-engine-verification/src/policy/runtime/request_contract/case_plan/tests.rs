use super::*;
use serde_json::json;

fn runtime(yaml: &str) -> RequestContracts {
    let mut owner = RequestContracts::default();
    owner
        .configure_compiled(Some(Arc::new(
            crate::policy::parse_and_compile_policy(yaml).unwrap(),
        )))
        .unwrap();
    let mut state = owner.state.lock().unwrap();
    for (case, method, path, protocol) in [
        ("selected", "GET", "/requests", ProtocolKind::Http),
        ("other", "POST", "/other", ProtocolKind::Motan),
    ] {
        state.cases.insert(
            case.into(),
            CaseAnchor::from_request(
                Path::new("unused"),
                &json!({"method":method,"uri":path}),
                &[],
            ),
        );
        state.primary_protocols.insert(case.into(), Some(protocol));
    }
    drop(state);
    owner
}

fn mysql() -> Value {
    json!({"event_type":"mysql_exchange","target_host":"db.test","target_port":3306,"database":"app","username":"user","command":"COM_QUERY","sql":"private SQL must not be retained"})
}

#[test]
fn format_and_pre_match_only_requirements_follow_each_cases_actual_carriers() {
    let mut owner = runtime(
        "format: traffic-policy/v3\njson:\n  fields:\n    /created_at: {kind: time, formats: [unix_seconds]}\n    /id: {kind: identity, formats: [uuid]}\nmysql:\n  tables:\n    jobs:\n      pattern: jobs\n      fields:\n        created_at: {kind: time, formats: [unix_seconds]}\n",
    );
    owner.configure_pre_match(true);
    owner.observe_plan_fact("selected", &mysql());
    owner.observe_plan_fact("selected",&json!({"event_type":"redis_exchange","target_host":"cache.test","target_port":6379,"database":0,"command":"SET"}));
    let plan = owner.prepare_case_rules("selected").unwrap();
    assert!(
        plan.plans.is_empty(),
        "global formats are independent of explicit value rules"
    );
    assert_eq!(
        plan.formats
            .iter()
            .map(|format| format.format)
            .collect::<Vec<_>>(),
        ["global.json", "global.mysql"]
    );
    assert_eq!(
        plan.pre_match_protocols,
        [ProtocolKind::Redis, ProtocolKind::Mysql]
    );
    assert!(plan.evidence.all_hypothesis_attempts && plan.evidence.independent_target);
    assert_eq!(
        plan.native_lookup_modes.get(&ProtocolKind::Mysql),
        Some(&"indexed")
    );
    assert!(
        plan.requirements
            .required
            .contains(&crate::value_contract::plan::IndexRequirement::SemanticLink)
    );
    let other = owner.prepare_case_rules("other").unwrap();
    assert!(other.pre_match_protocols.is_empty());
    assert_eq!(other.formats.len(), 1);
    assert_eq!(
        other.formats[0].eligible_protocols,
        [ProtocolKind::Motan],
        "native primary semantic assertion does not imply a generic typed-slot adapter"
    );
}

#[test]
fn unsupported_guessing_keeps_the_existing_native_matcher_and_explicit_reason() {
    let mut owner = runtime("format: traffic-policy/v3\n");
    owner.configure_pre_match(true);
    owner.observe_plan_fact("selected",&json!({"event_type":"memcached_exchange","target_host":"cache.test","target_port":11211,"command":"set"}));
    owner.observe_plan_fact("selected",&json!({"event_type":"motan_exchange","target_host":"rpc.test","target_port":8002,"method":"call","group":"g"}));
    owner.observe_plan_fact(
        "selected",
        &json!({"event_type":"kafka_fetch","target_host":"queue.test","target_port":9092}),
    );
    let plan = owner.prepare_case_rules("selected").unwrap();
    assert!(plan.pre_match_protocols.is_empty());
    assert_eq!(plan.unsupported_pre_match_protocols.len(), 3);
    assert!(
        plan.native_lookup_modes
            .values()
            .all(|mode| *mode == "existing_native")
    );
    assert!(!plan.evidence.all_hypothesis_attempts);
    assert_eq!(plan.summary()["eligible_rules"], 0);
}

#[test]
fn source_facts_retain_session_identity_and_never_payload_or_sql() {
    let owner = runtime("format: traffic-policy/v3\n");
    owner.observe_plan_fact("selected", &mysql());
    owner.observe_plan_fact("selected", &mysql());
    let state = owner.state.lock().unwrap();
    let facts = &state.source_plan_facts["selected"];
    assert_eq!(facts.len(), 1);
    let fact = facts.iter().next().unwrap();
    let resource: crate::policy::Resource = serde_yaml::from_str(
        "protocol: mysql\nendpoint: db.test:3306\ndatabase: app\nusername: user",
    )
    .unwrap();
    assert!(fact.matches_resource(&resource));
    let mut other = resource.clone();
    other.username = Some("someone_else".into());
    assert!(!fact.matches_resource(&other));
    assert!(!format!("{fact:?}").contains("private SQL"));
}

#[test]
fn source_facts_reuse_real_mysql_address_and_motan_method_fields() {
    let mut event = mysql();
    event.as_object_mut().unwrap().remove("target_host");
    event.as_object_mut().unwrap().remove("target_port");
    event["target_addr"] = json!("DB.TEST.:3306");
    let fact = SourceFact::from_event(&event).unwrap();
    assert_eq!(
        fact.target(),
        TargetKey {
            host: "db.test".into(),
            port: 3306
        }
    );
    assert_eq!(fact.operation.as_deref(), Some("COM_QUERY"));
    let event = json!({"event_type":"motan_exchange","target_host":"rpc.test","target_port":8002,"method_name":"create","command":"motan2:Service.create","group":"g"});
    let fact = SourceFact::from_event(&event).unwrap();
    assert_eq!(fact.operation.as_deref(), Some("create"));
    let mut coarse = event;
    coarse.as_object_mut().unwrap().remove("method_name");
    assert_eq!(
        SourceFact::from_event(&coarse)
            .unwrap()
            .operation
            .as_deref(),
        Some("motan2:Service.create")
    );
}

#[test]
fn primary_value_validation_is_source_selected_and_preserves_shared_plan_identity() {
    let mut document = crate::policy::TrafficPolicy::default();
    let rule:crate::policy::Rule = serde_yaml::from_str("id: elapsed\nsurface: api.response\nmatch: {api: GET /requests}\nslot: body\ncodec: json\ncontract:\n  /elapsed: {kind: duration, unit: seconds}\nproof: {source: 'clock.py:elapsed', fact: 'Source stores elapsed request seconds'}\n").unwrap();
    document.rules.push(rule.into());
    let compiled = Arc::new(crate::policy::compile_policy(&document).unwrap());
    let mut owner = runtime("format: traffic-policy/v3\n");
    owner.configure_compiled(Some(compiled.clone())).unwrap();
    let plan = owner.prepare_case_rules("selected").unwrap();
    assert_eq!(plan.plans.len(), 1);
    assert!(Arc::ptr_eq(
        &plan.plans[0],
        &compiled.rules[0].execution_plan
    ));
    assert!(owner.prepare_case_rules("other").unwrap().plans.is_empty());
    owner
        .state
        .lock()
        .unwrap()
        .primary_protocols
        .insert("selected".into(), Some(ProtocolKind::Motan));
    let error = owner.prepare_case_rules("selected").unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("protocol=motan"));
    assert!(diagnostic.contains("adapter is not installed"));
}

#[test]
fn api_postings_keep_the_runtime_catch_all_parent_boundary() {
    // Build through a genuine compiled rule, preserving the compiler's selector
    // validation and the runtime's whole-segment path grammar.
    let mut document = crate::policy::TrafficPolicy::default();
    let rule:crate::policy::Rule = serde_yaml::from_str("id: elapsed\nsurface: api.response\nmatch: {api: 'GET /requests/**'}\nslot: body\ncodec: json\ncontract:\n  /elapsed: {kind: duration, unit: seconds}\nproof: {source: 'clock.py:elapsed', fact: 'Source stores elapsed request seconds'}\n").unwrap();
    document.rules.push(rule.into());
    let compiled = crate::policy::compile_policy(&document).unwrap();
    let catalogue = RuleCatalogue::new(&compiled);
    let parent = CaseAnchor::from_request(
        Path::new("unused"),
        &json!({"method":"GET","uri":"/requests"}),
        &[],
    );
    let child = CaseAnchor::from_request(
        Path::new("unused"),
        &json!({"method":"GET","uri":"/requests/1"}),
        &[],
    );
    assert!(catalogue.candidates(&parent, None).is_empty());
    assert_eq!(catalogue.candidates(&child, None).len(), 1);
}
