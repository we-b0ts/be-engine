use super::*;
use crate::config::process_owned_dependencies::mysql::evidence::fingerprint;
use crate::{ApiTriggeredMysqlSelector, BackgroundDependencyRuleConfig, plan_api_triggered_mysql};

pub(super) fn mysql_selector() -> ApiTriggeredMysqlSelector {
    ApiTriggeredMysqlSelector {
        include_transaction_boundaries: false,
        transaction_members: Vec::new(),
        selector: serde_json::from_value(json!({"target_host":"db.test","target_port":3306,
            "database":"app","username":"writer","sql":"SELECT id FROM {{table}} WHERE id=? LIMIT 1",
            "table_patterns":["jobs_*"]})).unwrap(),
        trigger_source: source(), identity_value_index: 0,
    }
}

pub(super) fn read(id: u64) -> Value {
    json!({"event_type":"mysql_exchange","command":"COM_QUERY","target_host":"db.test","target_port":3306,
        "database":"app","username":"writer","outcome":"response","parse_warnings":[],
        "timestamp":"2026-10-12T11:00:02Z","connection_id":"mysql-lane","query_sequence":1,
        "sql":format!("SELECT id FROM jobs_0001 WHERE id={id} LIMIT 1"),
        "response":{"status":"resultset","columns":[{"name":"id"}],"rows":[[id]],"row_count":1,"rows_truncated":false}})
}

#[test]
fn integral_identity_capture_preserves_trailing_zeros_and_large_numeric_predicates() {
    for id in [
        10,
        120,
        1_000,
        893_215_758_816_130,
        18_446_744_073_709_551_610,
    ] {
        let f = Fixture::mysql();
        f.mysql_events(&[read(id)]);
        write_lines(&f.origin.join("dependencies.jsonl"), &[insert(id)]);
        let mut selector = mysql_selector();
        selector
            .trigger_source
            .capture
            .values_mut()
            .next()
            .unwrap()
            .row_match
            .insert("id".into(), id.into());
        let index = load(
            &f.root,
            &[selector.rule("integer-id", SOURCE_REVISION, PROOF)],
        )
        .unwrap();
        assert_eq!(
            index
                .witness("victim", &read(id))
                .unwrap()
                .captured_identity,
            id.to_string()
        );
        let event = redis("DEL", id, "victim-lane");
        write_lines(
            &f.victim.join("dependencies.jsonl"),
            std::slice::from_ref(&event),
        );
        let index = load(&f.root, &f.rules("DEL")).unwrap();
        assert!(index.witness("victim", &event).is_some());
    }
    for sql in [
        "INSERT INTO jobs_0001 (id,role) VALUES (-120,'ASSISTANT')",
        "INSERT INTO jobs_0001 (id,role) VALUES (1.2,'ASSISTANT')",
        "INSERT INTO jobs_0001 (id,role) VALUES (184467440737095516160,'ASSISTANT')",
    ] {
        let mut e = insert(12);
        e["sql"] = sql.into();
        assert!(
            super::super::evidence::capture_identity(source().capture.values().next().unwrap(), &e)
                .is_none()
        );
    }
}

fn summary(case: &str, event: &Value, index: usize) -> Value {
    json!({"index":index,"case_id":case,"command":event["command"],"target":{"host":event["target_host"],"port":event["target_port"]},
        "database":event["database"],"username":event["username"],"status":"resultset",
        "sql_summary":{"preview":"incomplete preview","truncated":true,"fingerprint":fingerprint(event["sql"].as_str().unwrap())}})
}

impl Fixture {
    pub(super) fn mysql() -> Self {
        let f = Self::new("DEL");
        f.mysql_events(&[read(12)]);
        f
    }
    pub(super) fn mysql_events(&self, events: &[Value]) {
        write_lines(
            &self.origin.join("dependencies.jsonl"),
            &[insert(12), read(12)],
        );
        write_lines(&self.victim.join("dependencies.jsonl"), events);
        let mut report: Value = serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap();
        report["redis"]["unused_case"] = json!([]);
        let mut unused = vec![summary("origin", &read(12), 0)];
        unused.extend(
            events
                .iter()
                .enumerate()
                .map(|(i, e)| summary("victim", e, i + 1)),
        );
        report["unused_case_exchanges"] = unused.into();
        report["unused_global_exchanges"] = json!([]);
        report["unmatched_queries"] = json!([]);
        report["unsupported_commands"] = json!([]);
        fs::write(&self.report, report.to_string()).unwrap();
    }
    pub(super) fn mysql_rules(&self) -> Vec<BackgroundDependencyRuleConfig> {
        vec![mysql_selector().rule("job-result", SOURCE_REVISION, PROOF)]
    }
    pub(super) fn mysql_plan(&self) -> anyhow::Result<crate::ApiTriggeredMysqlPlan> {
        plan_api_triggered_mysql(
            &self.policy,
            &self.report,
            &self.root,
            "job-result",
            SOURCE_REVISION,
            PROOF,
            &mysql_selector(),
        )
    }
    pub(super) fn mysql_overlay(&self) -> Value {
        let before = fs::read(&self.report).unwrap();
        crate::replay::reclassify_background_dependencies(
            &self.policy,
            &self.report,
            &std::collections::BTreeMap::from([
                ("origin".into(), self.origin.clone()),
                ("victim".into(), self.victim.clone()),
            ]),
        )
        .unwrap();
        let after = fs::read(&self.report).unwrap();
        assert_eq!(
            before, after,
            "proof discovery must not rewrite actual Replay"
        );
        serde_json::from_slice(&after).unwrap()
    }
}

#[test]
fn mysql_old_recording_plan_apply_cache_and_removal_preserve_owner_and_finite_counts() {
    let f = Fixture::mysql();
    let mut second = read(12);
    second["query_sequence"] = 2.into();
    f.mysql_events(&[read(12), second]);
    let original = fs::read(f.victim.join("dependencies.jsonl")).unwrap();
    let cold = load(&f.root, &f.mysql_rules()).unwrap();
    assert_eq!(cold.witnesses.len(), 1);
    assert_eq!(cold.witnesses.values().next().unwrap().exchanges, 2);
    let warm = load(&f.root, &f.mysql_rules()).unwrap();
    assert!(warm.cache_reused);
    assert_eq!(warm.source_bytes, 0);
    let plan = f.mysql_plan().unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 2);
    assert_eq!(plan.report().trigger_case_ids, ["origin"]);
    plan.apply().unwrap();
    for _ in 0..2 {
        let report = f.mysql_overlay();
        assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 3);
        assert_eq!(report["unused_global_exchanges"], json!([]));
    }
    assert!(!f.mysql_plan().unwrap().report().changed);
    fs::write(
        &f.policy,
        SourceTrafficPolicyConfig::empty().render().unwrap(),
    )
    .unwrap();
    let report = f.mysql_overlay();
    assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 3);
    assert_eq!(report["unused_global_exchanges"], json!([]));
    assert!(
        report["unused_case_exchanges"][1]
            .get("api_trigger_source")
            .is_none()
    );
    assert_eq!(
        original,
        fs::read(f.victim.join("dependencies.jsonl")).unwrap()
    );
}

#[test]
fn mysql_requires_exact_identity_endpoint_shape_and_complete_duplicates() {
    for mode in 0..9 {
        let f = Fixture::mysql();
        let mut e = read(12);
        match mode {
            0 => e = read(99),
            1 => e["target_host"] = "another.test".into(),
            2 => e["database"] = "other".into(),
            3 => e["username"] = "other".into(),
            4 => e["sql"] = "SELECT id FROM jobs_0001 WHERE id=12 LIMIT 2".into(),
            5 => e["response"]["rows_truncated"] = true.into(),
            6 => e["timestamp"] = "2026-10-12T11:00:00Z".into(),
            7 => e["parse_warnings"] = json!(["incomplete"]),
            _ => e["outcome"] = "error".into(),
        }
        f.mysql_events(&[e]);
        assert!(
            load(&f.root, &f.mysql_rules())
                .unwrap()
                .witnesses
                .is_empty(),
            "mode={mode}"
        );
        assert!(f.mysql_plan().is_err());
    }
    for reverse in [false, true] {
        let f = Fixture::mysql();
        let mut incomplete = read(12);
        incomplete["response"]["rows_truncated"] = true.into();
        let events = if reverse {
            vec![incomplete, read(12)]
        } else {
            vec![read(12), incomplete]
        };
        f.mysql_events(&events);
        assert!(
            load(&f.root, &f.mysql_rules())
                .unwrap()
                .witnesses
                .is_empty()
        );
    }
}

#[test]
fn mysql_same_identity_reads_use_existing_origin_rules() {
    for uri in ["/jobs/resp_12/cancel", "/jobs/resp_12", "/items?job=12"] {
        let f = Fixture::mysql();
        f.change_request(&f.victim, json!({}), uri);
        let index = load(&f.root, &f.mysql_rules()).unwrap();
        assert_eq!(index.witnesses.len(), 1, "{uri}");
        assert!(index.witnesses.values().all(|w| w.same_resource_read));
    }
    let f = Fixture::mysql();
    f.change_request(&f.victim, json!({"id":12}), "/items");
    assert_eq!(f.mysql_plan().unwrap().report().matched_unused_exchanges, 1);
}

#[test]
fn same_route_and_other_resources_allow_proven_foreign_mysql_calls() {
    for uri in ["/jobs", "/jobs/resp_99", "/jobs/resp_99/cancel"] {
        let f = Fixture::mysql();
        f.change_request(&f.victim, json!({}), uri);
        assert_eq!(load(&f.root, &f.mysql_rules()).unwrap().witnesses.len(), 1);
        f.mysql_plan().unwrap().apply().unwrap();
        let overlay = f.mysql_overlay();
        assert_eq!(
            overlay["unused_case_exchanges"].as_array().unwrap().len(),
            2
        );
    }
}

#[test]
fn mysql_binding_accepts_singleton_in_and_rejects_unbounded_or_non_predicate_slots() {
    let mut selector = mysql_selector();
    selector.selector.sql =
        "SELECT id FROM {{table}} WHERE subtask_id IN (?) ORDER BY id ASC".into();
    let mut e = read(12);
    e["sql"] = "SELECT id FROM jobs_0001 WHERE subtask_id IN (12) ORDER BY id ASC".into();
    let rule = selector.rule("x", SOURCE_REVISION, PROOF);
    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule)).unwrap();
    assert_eq!(
        crate::config::api_trigger::mysql::identity(&rule, &e).as_deref(),
        Some("12")
    );
    for sql in [
        "SELECT ? FROM {{table}} WHERE id=12",
        "SELECT id FROM {{table}} WHERE id=12 LIMIT ?",
        "SELECT id FROM {{table}} WHERE id=? OR active=1",
        "SELECT id FROM {{table}} WHERE NOT id=?",
        "SELECT id FROM {{table}} WHERE id IN (?,?)",
        "SELECT id FROM {{table}} WHERE id IN (?)=0",
        "DELETE FROM {{table}} WHERE id=?",
    ] {
        selector.selector.sql = sql.into();
        assert!(
            crate::config::process_owned_dependencies::validate(&[selector.rule(
                "x",
                SOURCE_REVISION,
                PROOF
            )])
            .is_err(),
            "{sql}"
        );
    }
    let mut selector = mysql_selector();
    selector.identity_value_index = 1;
    assert!(
        crate::config::process_owned_dependencies::validate(&[selector.rule(
            "x",
            SOURCE_REVISION,
            PROOF
        )])
        .is_err()
    );
}

#[test]
fn mysql_same_name_ordinary_rule_is_narrowed_and_never_reused_as_broad_proof() {
    let f = Fixture::mysql();
    let mut ordinary = f.mysql_rules().remove(0);
    if let BackgroundDependencyRuleConfig::Mysql {
        trigger_source,
        identity_value_index,
        ..
    } = &mut ordinary
    {
        *trigger_source = None;
        *identity_value_index = None;
    }
    let mut policy = SourceTrafficPolicyConfig::empty();
    policy.process_owned_dependencies = vec![ordinary];
    fs::write(&f.policy, policy.render().unwrap()).unwrap();
    assert_eq!(
        f.mysql_overlay()["unused_global_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let plan = f.mysql_plan().unwrap();
    assert!(plan.report().changed);
    assert!(!plan.report().reused_existing);
    assert_eq!(plan.report().matched_unused_exchanges, 1);
    plan.apply().unwrap();
    assert_eq!(
        f.mysql_overlay()["unused_global_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn mysql_plan_rejects_target_failures_foreign_membership_and_duplicate_report_witnesses() {
    for mode in 0..4 {
        let f = Fixture::mysql();
        let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
        match mode {
            0 => {
                report["unmatched_queries"] = json!([{"target":{"host":"db.test","port":3306},"database":"app","username":"writer"}])
            }
            1 => {
                report["cases"][1]["dependencies_path"] =
                    "/another-recording/dependencies.jsonl".into()
            }
            2 => {
                let e = report["unused_case_exchanges"][1].clone();
                report["unused_case_exchanges"]
                    .as_array_mut()
                    .unwrap()
                    .push(e);
            }
            _ => {
                report["unused_case_exchanges"][1]["sql_summary"]["fingerprint"] =
                    "fnv1a64:incorrect".into()
            }
        }
        fs::write(&f.report, report.to_string()).unwrap();
        assert!(f.mysql_plan().is_err(), "mode={mode}");
    }
}

#[test]
fn mysql_bound_execute_sql_is_supported_without_interpreting_unbound_parameters() {
    let f = Fixture::mysql();
    let mut e = read(12);
    e["command"] = "COM_STMT_EXECUTE".into();
    f.mysql_events(&[e.clone()]);
    assert_eq!(f.mysql_plan().unwrap().report().matched_unused_exchanges, 1);
    e["sql"] = "SELECT id FROM jobs_0001 WHERE id=? LIMIT 1".into();
    f.mysql_events(&[e]);
    assert!(f.mysql_plan().is_err());
}

#[test]
fn mysql_apply_rejects_source_changes_and_mixed_redis_rules_share_origin_index() {
    let f = Fixture::mysql();
    let plan = f.mysql_plan().unwrap();
    f.change_request(&f.origin, json!({"background":false}), "/jobs");
    assert!(plan.apply().is_err());
    let f = Fixture::mysql();
    write_lines(
        &f.victim.join("dependencies.jsonl"),
        &[read(12), redis("DEL", 12, "victim-lane")],
    );
    let mut rules = f.mysql_rules();
    rules.extend(f.rules("DEL"));
    let index = load(&f.root, &rules).unwrap();
    assert_eq!(index.witnesses.len(), 2);
}

#[tokio::test]
async fn mysql_recorder_retains_idle_candidates_and_keeps_active_calls_case_owned() {
    use crate::recorder::{
        CaseContext, MysqlColumn, MysqlExchangeEvent, MysqlExchangeResponse, RecorderEvent,
    };
    use uuid::Uuid;
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.dns_mock.registry_path = temp.path().join("dns.json");
    config.http_gateway.ready.enabled = false;
    config.process_owned_dependencies =
        vec![mysql_selector().rule("background", SOURCE_REVISION, PROOF)];
    let state = crate::AppState::new(config).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "items".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let event = || {
        RecorderEvent::MysqlExchange(MysqlExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            query_sequence: 1,
            timestamp: chrono::Utc::now(),
            client_addr: None,
            route_name: None,
            target_host: Some("db.test".into()),
            target_port: Some(3306),
            target_addr: Some("db.test:3306".into()),
            upstream_addr: None,
            username: Some("writer".into()),
            database: Some("app".into()),
            command: "COM_QUERY".into(),
            sql: Some("SELECT id FROM jobs_0001 WHERE id=12 LIMIT 1".into()),
            statement_id: None,
            params: None,
            server_status_before: None,
            response: MysqlExchangeResponse {
                wire_prefix: Vec::new(),
                server_status: None,
                status: "resultset".into(),
                error_code: None,
                error_message: None,
                affected_rows: None,
                last_insert_id: None,
                columns: vec![MysqlColumn {
                    database: None,
                    name: "id".into(),
                    table: None,
                    column: None,
                    family: "integer".into(),
                    sql_type: "BIGINT".into(),
                    unsigned: Some(true),
                    bits: Some(64),
                    nullable: Some(false),
                    scale: None,
                    column_type_code: 8,
                    flags: None,
                }],
                rows: vec![],
                row_count: 0,
                rows_truncated: false,
            },
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 1,
            parse_warnings: vec![],
        })
    };
    state.record_event(event());
    drop(guard);
    state.recorder().publish_case(&case).await.unwrap();
    state.record_event(event());
    state.recorder().finish_run().await.unwrap();
    let own = crate::recorder::test_io::read_to_string_sync(
        state.recorder().case_dir(&case).join("dependencies.jsonl"),
    )
    .unwrap();
    let global = crate::recorder::test_io::read_to_string_sync(
        state
            .recorder()
            .run_dir
            .join("indexes/unattributed-scope.json"),
    )
    .unwrap();
    assert_eq!(own.lines().count(), 1);
    assert_eq!(global.lines().count(), 1);
    assert!(own.contains("\"kind\":\"case\""));
    assert!(global.contains("\"kind\":\"unattributed\""));
}
