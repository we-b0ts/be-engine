use super::*;
use serde_json::json;

const A: &str = "00000000-0000-4000-8000-000000000001";
const X: &str = "00000000-0000-4000-8000-000000000002";

#[test]
fn inferred_mysql_delivery_shares_identity_and_publishes_copies_only_after_wire() {
    let compiled = crate::policy::parse_and_compile_policy(&json!({
        "format":"traffic-policy/v2",
        "json":{"fields":{"/item_id":{"kind":"identity","formats":["uuid"]},"/created_at":{"kind":"time","formats":["unix_seconds"]}}},
        "mysql":{"tables":{"tasks":{"pattern":"tasks","fields":{"id":{"kind":"identity","formats":["uuid"]}}}}}
    }).to_string()).unwrap();
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner.state.lock().unwrap().cases.insert(
        "case".into(),
        CaseAnchor {
            method: "GET".into(),
            path: "/anywhere".into(),
            source_uri: String::new(),
            source_input_error: None,
            recorded: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            actual: Some("2026-01-01T00:00:00Z".parse().unwrap()),
            dir: PathBuf::new(),
            conditions: Default::default(),
            source_body: None,
        },
    );
    let mapped = owner
        .preview_identity_pairs(
            "case",
            &[crate::value_contract::identities::IdentityPair {
                source: serde_json::to_string(A).unwrap(),
                target: serde_json::to_string(X).unwrap(),
            }],
        )
        .unwrap();
    owner.commit_identity(mapped).unwrap();
    let payload = format!(
        r#"{{ "stable":7,"mcpServers":{{"zeta":{{"url":"z"}},"alpha":{{"baseUrl":"a"}}}}, "item_id":"{A}","created_at":1577836805 }}"#
    );
    let event = json!({"event_type":"mysql_exchange","command":"COM_QUERY","database":"app","target_host":"db.test","target_port":3306,
        "sql":"SELECT id,payload,created_at FROM tasks","timestamp":"2020-01-01T00:00:00Z","duration_ms":0,
        "response":{"status":"resultset","columns":[
            {"name":"id","database":"app","table":"tasks","column":"id","sql_type":"VARCHAR","family":"string"},
            {"name":"payload","database":"app","table":"tasks","column":"payload","sql_type":"TEXT","family":"string"},
            {"name":"created_at","database":"app","table":"tasks","column":"created_at","sql_type":"DATETIME","family":"datetime"}
        ],"rows":[[{"kind":"string","value":A},{"kind":"string","value":payload},{"kind":"datetime","value":"2020-01-01 00:00:05"}]],"rows_truncated":false}});
    owner.observe_unified_mysql_source("case", &event).unwrap();
    let record: RecordedMysqlExchange = serde_json::from_value(event).unwrap();
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    };
    let request = crate::replay::mysql::contracts::ObservedRequest {
        observation_id: None,
        command: "COM_QUERY",
        sql: record.sql.as_deref(),
        params: None,
        started_at: "2026-01-01T00:00:00Z".parse().unwrap(),
    };
    let prepared = crate::replay::mysql::contracts::prepare_delivery(
        &owner,
        "case",
        &identity,
        &record,
        &record.response,
        request,
    )
    .unwrap()
    .unwrap();
    let copies = crate::replay::mysql::contracts::time_copies::prepare(
        &owner,
        "case",
        &identity,
        &record,
        &record.response,
        record.sql.as_deref(),
    )
    .unwrap()
    .unwrap();
    let (delivered, identities) = prepared.render(request.started_at).unwrap();
    assert_eq!(delivered.rows[0][0].value.as_ref().unwrap(), &json!(X));
    let rendered: Value = serde_json::from_str(
        delivered.rows[0][1]
            .value
            .as_ref()
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rendered["item_id"], X);
    assert_eq!(rendered["created_at"], 1767225605_i64);
    assert_eq!(
        delivered.rows[0][1]
            .value
            .as_ref()
            .unwrap()
            .as_str()
            .unwrap(),
        payload.replace(A, X).replace("1577836805", "1767225605")
    );
    assert_eq!(
        delivered.rows[0][2].value.as_ref().unwrap(),
        &json!("2026-01-01 00:00:05")
    );
    assert_eq!(
        record.response.rows[0][0].value.as_ref().unwrap(),
        &json!(A)
    );

    let source_sql = format!(
        "UPDATE tasks SET payload='{payload}',created_at='2020-01-01 00:00:05' WHERE id='{A}'"
    );
    let target_sql = format!(
        "UPDATE tasks SET payload='{rendered}',created_at='2026-01-01 00:00:05' WHERE id='{X}'"
    );
    let source_record: RecordedMysqlExchange = serde_json::from_value(
        json!({"command":"COM_QUERY","sql":source_sql,"database":"app","response":{"status":"ok"}}),
    )
    .unwrap();
    let clocks = owner.contract_clocks(
        Some("case"),
        Some("2020-01-01T00:01:00Z".parse().unwrap()),
        Some("2026-01-01T00:02:00Z".parse().unwrap()),
        None,
        None,
    );
    let context = crate::replay::mysql::contracts::automatic::RequestContext::new(
        owner.compiled_rules().unwrap(),
        owner.mysql_automatic.lock().unwrap().clone(),
        &identity,
        &source_record,
    );
    let compare = |target: &str| {
        super::super::super::matcher::mysql_native::compare_with_automatic(
            Some("app"),
            source_record.sql.as_deref(),
            None,
            Some(target),
            None,
            &[],
            &[],
            clocks,
            Some(
                super::super::super::matcher::mysql_native::CopyProofs::runtime(
                    &owner,
                    "case",
                    clocks.dependency,
                ),
            ),
            &context,
        )
    };
    assert!(
        compare(&target_sql).is_err(),
        "preparing a read is not successful delivery"
    );
    copies
        .commit(
            &owner,
            Some("case"),
            &identity,
            &delivered,
            record.sql.as_deref(),
            request.started_at,
        )
        .unwrap();
    prepared
        .commit(&owner, &delivered, request.started_at, identities)
        .unwrap();
    let comparison = compare(&target_sql).unwrap();
    assert!(comparison.passed(), "{:?}", comparison.differences);
    assert!(compare(&target_sql.replace("\"stable\":7", "\"stable\":8")).is_err());
    owner.clear_time_copies("case");
    assert!(compare(&target_sql).is_err());
}
