use super::*;
use serde_json::json;
use std::fs;

fn runtime() -> RequestContracts {
    let policy = crate::policy::parse_and_compile_policy(&json!({"format":"traffic-policy/v2","rules":[{
        "id":"time","surface":"dependency.request","match":{
            "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},
            "tables":["tasks"]},"slot":{"sql_field":"updated_at"},"codec":"scalar",
        "contract":{"":{"relative_time":"sql_datetime"}},
        "proof":{"source":"models.py:update","fact":"The physical audit column follows its own request clock across accesses"}
    }]}).to_string()).unwrap();
    let mut runtime = RequestContracts::default();
    runtime.configure_compiled(Some(Arc::new(policy))).unwrap();
    runtime
}

fn identity(database: &str) -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some(database.into()),
        username: Some("writer".into()),
    }
}

fn record(sql: &str) -> RecordedMysqlExchange {
    serde_json::from_value(
        json!({"command":"COM_QUERY","database":"app","sql":sql,"response":{"status":"ok"}}),
    )
    .unwrap()
}

#[test]
fn resource_field_scope_selects_new_sql_without_api_or_statement_filter() {
    let runtime = runtime();
    let session = identity("app");
    for sql in [
        "UPDATE tasks SET updated_at='2020-01-01 00:00:01' WHERE id=7",
        "SELECT id FROM tasks WHERE updated_at > '2020-01-01 00:00:01'",
        "INSERT INTO tasks(id,updated_at) VALUES(7,'2020-01-01 00:00:01')",
    ] {
        let record = record(sql);
        assert_eq!(
            runtime
                .mysql_compiled_rules(Surface::DependencyRequest, None, &session, &record)
                .len(),
            1
        );
        assert!(runtime.mysql_fields_metadata_matches(
            None,
            &session,
            &record,
            &sql.replace("'2020-01-01 00:00:01'", "?")
        ));
        assert!(!runtime.mysql_fields_metadata_matches(
            None,
            &session,
            &record,
            &sql.replace("tasks", "jobs")
        ));
    }
    let record = record("UPDATE tasks SET updated_at='2020-01-01 00:00:01' WHERE id=7");
    assert!(
        runtime
            .mysql_compiled_rules(
                Surface::DependencyRequest,
                None,
                &identity("other"),
                &record
            )
            .is_empty()
    );
}

#[test]
fn qualified_schema_overrides_connection_default_without_weakening_resource_guards() {
    let runtime = runtime();
    let mut record = record("UPDATE app.tasks SET updated_at='2020-01-01 00:00:01' WHERE id=7");
    record.database = Some("other".into());
    let mut identity = identity("other");
    assert_eq!(
        runtime
            .mysql_compiled_rules(Surface::DependencyRequest, None, &identity, &record)
            .len(),
        1
    );
    identity.username = Some("other".into());
    assert!(
        runtime
            .mysql_compiled_rules(Surface::DependencyRequest, None, &identity, &record)
            .is_empty()
    );
}

#[test]
fn mixed_schema_preview_grants_only_the_observed_physical_field() {
    let runtime = runtime();
    let source = "SELECT a.id FROM app.tasks a JOIN tasks b ON a.id=b.id WHERE a.updated_at='2020-01-01 00:00:01' AND b.updated_at='2020-01-01 00:00:02'";
    let target = source.replace("a.updated_at='2020-01-01", "a.updated_at='2026-01-01");
    let mut record = record(source);
    record.database = Some("other".into());
    record.timestamp = Some("2020-01-01T00:00:00Z".parse().unwrap());
    let session = identity("other");
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("policy.yaml"),
        "format: traffic-policy/v2\nrules: []\n",
    )
    .unwrap();
    let owner = super::super::super::matcher::ReplayPolicyRuntime::load(
        &directory.path().join("policy.yaml"),
        &BTreeMap::new(),
    )
    .unwrap();
    let preview = |sql: &str| {
        runtime.preview_mysql_values(
            None,
            &session,
            &record,
            "COM_QUERY",
            Some(sql),
            None,
            "2026-01-01T00:00:00Z".parse().unwrap(),
            &owner,
        )
    };
    assert!(preview(&target).unwrap().is_ok());
    assert!(
        preview(&target.replace("b.updated_at='2020-01-01", "b.updated_at='2026-01-01"))
            .unwrap()
            .is_err()
    );
    assert!(!runtime.mysql_fields_metadata_matches(
        None,
        &identity("app"),
        &record,
        &source.replace("'2020-01-01 00:00:01'", "?"),
    ));
    let mut unknown = record.clone();
    unknown.database = None;
    let mut unknown_session = session;
    unknown_session.database = None;
    assert!(
        runtime
            .mysql_compiled_rules(Surface::DependencyRequest, None, &unknown_session, &unknown)
            .is_empty()
    );
}
