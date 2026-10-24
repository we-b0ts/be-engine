use super::*;
use serde_json::json;

const A: &str = "00000000-0000-4000-8000-000000000001";
const X: &str = "00000000-0000-4000-8000-000000000002";
const Y: &str = "00000000-0000-4000-8000-000000000003";

fn policy() -> CompiledPolicy {
    crate::policy::parse_and_compile_policy(&json!({
        "format":"traffic-policy/v2",
        "json":{"fields":{"/item_id":{"kind":"identity","formats":["uuid"]}}},
        "mysql":{"database":"app","tables":{"tasks":{"pattern":"tasks","fields":{"id":{"kind":"identity","formats":["uuid"]}}}}}
    }).to_string()).unwrap()
}

fn identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    }
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T00:00:00.123456Z".parse().unwrap()),
            target: Some("2026-01-01T00:00:00.234567Z".parse().unwrap()),
        },
        ..Default::default()
    }
}

fn record(sql: &str) -> RecordedMysqlExchange {
    serde_json::from_value(
        json!({"command":"COM_QUERY","sql":sql,"database":"app","response":{"status":"ok"}}),
    )
    .unwrap()
}

fn compare(
    policy: &CompiledPolicy,
    metadata: Metadata,
    source: &RecordedMysqlExchange,
    target: &str,
) -> Result<Comparison> {
    let identity = identity();
    let context = RequestContext::new(policy, metadata, &identity, source);
    policy::compare_mysql_with_automatic(
        Some("app"),
        source.sql.as_deref(),
        source.params.as_deref(),
        Some(target),
        None,
        &[],
        &[],
        clocks(),
        None,
        &context,
    )
}

#[test]
fn scalar_ids_and_json_ids_share_one_automatic_correspondence() {
    let policy = policy();
    let source = record(&format!(
        "INSERT INTO tasks(id,payload,count) VALUES('{A}','{{\"item_id\":\"{A}\"}}',7)"
    ));
    let target =
        format!("INSERT INTO tasks(id,payload,count) VALUES('{X}','{{\"item_id\":\"{X}\"}}',7)");
    let passed = compare(&policy, Metadata::default(), &source, &target).unwrap();
    assert!(passed.passed(), "{:?}", passed.differences);
    assert!(passed.evaluated.contains("global.mysql"));
    assert!(passed.evaluated.contains("global.json"));
    let mismatch = target.replace(&format!("item_id\":\"{X}"), &format!("item_id\":\"{Y}"));
    assert!(
        !compare(&policy, Metadata::default(), &source, &mismatch)
            .unwrap()
            .passed()
    );
    assert!(
        compare(
            &policy,
            Metadata::default(),
            &source,
            &target.replace(",7)", ",8)")
        )
        .is_err()
    );
}

fn temporal_record(sql_type: &str, family: &str, value: &str) -> RecordedMysqlExchange {
    serde_json::from_value(json!({"command":"COM_QUERY","sql":"SELECT created_at FROM tasks","database":"app",
        "response":{"status":"resultset","columns":[{"name":"created_at","database":"app","table":"tasks","column":"created_at","family":family,"sql_type":sql_type}],
        "rows":[[{"kind":family,"value":value}]],"rows_truncated":false}})).unwrap()
}

#[test]
fn native_metadata_infers_time_for_later_writes_without_field_declarations() {
    let mut policy = policy();
    policy.mysql = None; // A global JSON policy enables native schema inference.
    let source = record("UPDATE tasks SET created_at='2020-01-01 08:00:01.123456' WHERE count=7");
    let mut metadata = Metadata::default();
    metadata.observe(
        &identity(),
        &temporal_record("DATETIME", "datetime", "2020-01-01 08:00:01.123456"),
    );
    let passed = compare(
        &policy,
        metadata.clone(),
        &source,
        "UPDATE tasks SET created_at='2026-01-01 08:00:01.234567' WHERE count=7",
    )
    .unwrap();
    assert!(passed.passed(), "{:?}", passed.differences);
    assert!(
        compare(
            &policy,
            metadata,
            &source,
            "UPDATE tasks SET created_at='2026-01-01 08:01:01.234567' WHERE count=7"
        )
        .is_err()
    );
    let mut string_metadata = Metadata::default();
    string_metadata.observe(
        &identity(),
        &temporal_record("VARCHAR", "string", "2020-01-01 08:00:01.123456"),
    );
    assert!(
        compare(
            &policy,
            string_metadata,
            &source,
            "UPDATE tasks SET created_at='2026-01-01 08:00:01.234567' WHERE count=7"
        )
        .is_err()
    );
}

#[test]
fn native_null_zero_and_unknown_types_remain_exact() {
    let policy = policy();
    let source = temporal_record("DATE", "date", "0000-00-00");
    let same = compare_response(
        &policy,
        &source.response,
        &source.response,
        None,
        Some("app"),
        clocks(),
    )
    .unwrap();
    assert!(same.passed());
    assert!(same.time_validations.is_empty());
    let mut target = source.response.clone();
    target.rows[0][0].value = Some(json!("2026-01-01"));
    assert!(
        !compare_response(
            &policy,
            &source.response,
            &target,
            None,
            Some("app"),
            clocks()
        )
        .unwrap()
        .passed()
    );
    let mut null = source.response.clone();
    null.rows[0][0] = serde_json::from_value(json!({"kind":"null"})).unwrap();
    assert!(
        compare_response(&policy, &null, &null, None, Some("app"), clocks())
            .unwrap()
            .passed()
    );
    assert!(compare_response(&policy, &null, &target, None, Some("app"), clocks()).is_err());
}

#[test]
fn native_datetime_delivery_preserves_fractional_precision() {
    let owner = policy::request_contract::RequestContracts::default();
    for (source, expected) in [
        ("2020-01-01 00:00:01", "2026-01-01 00:00:01"),
        ("2020-01-01 00:00:01.123456", "2026-01-01 00:00:01.234567"),
    ] {
        let selected =
            temporal_selection(json!(source), json!(source), Temporal::Datetime).unwrap();
        let (logical, _) = translate_selection(&owner, "case", &selected, clocks()).unwrap();
        assert_eq!(logical, json!(expected));
    }
    let selected =
        temporal_selection(json!("2020-01-01"), json!("2020-01-01"), Temporal::Date).unwrap();
    let (logical, _) = translate_selection(&owner, "case", &selected, clocks()).unwrap();
    assert_eq!(logical, json!("2026-01-01"));
}

#[test]
fn mysql_json_needs_no_table_or_column_codec_declaration() {
    let mut policy = policy();
    policy.mysql = None;
    let mut source = temporal_record(
        "VARCHAR",
        "string",
        &format!("{{\"item_id\":\"{A}\",\"stable\":7}}"),
    );
    let mut target = source.response.clone();
    target.rows[0][0].value = Some(json!(format!("{{\"item_id\":\"{X}\",\"stable\":7}}")));
    let result = compare_response(
        &policy,
        &source.response,
        &target,
        None,
        Some("app"),
        clocks(),
    )
    .unwrap();
    assert!(result.passed(), "{:?}", result.differences);
    target.rows[0][0].value = Some(json!(format!("{{\"item_id\":\"{X}\",\"stable\":8}}")));
    assert!(
        !compare_response(
            &policy,
            &source.response,
            &target,
            None,
            Some("app"),
            clocks()
        )
        .unwrap()
        .passed()
    );
    source.response.rows[0][0].value = Some(json!("opaque"));
    assert!(
        compare_response(
            &policy,
            &source.response,
            &target,
            None,
            Some("app"),
            clocks()
        )
        .is_err()
    );
}

#[test]
fn mysql_database_limits_scalar_and_native_inference_without_limiting_json() {
    let policy = policy();
    let source = record(&format!("UPDATE other.tasks SET id='{A}'"));
    assert!(
        compare(
            &policy,
            Metadata::default(),
            &source,
            &format!("UPDATE other.tasks SET id='{X}'")
        )
        .is_err()
    );
    let mut read = temporal_record("DATETIME", "datetime", "2020-01-01 00:00:01");
    read.response.columns[0].database = Some("other".into());
    let mut target = read.response.clone();
    target.rows[0][0].value = Some(json!("2026-01-01 00:00:01"));
    assert!(
        compare_response(
            &policy,
            &read.response,
            &target,
            None,
            Some("app"),
            clocks()
        )
        .is_err()
    );
}

#[test]
fn equal_native_times_need_no_clock_and_historical_delivery_retains_original_value() {
    let selected = temporal_selection(
        json!("1970-01-01 00:00:00"),
        json!("1970-01-01 00:00:00"),
        Temporal::Datetime,
    )
    .unwrap();
    let comparison = compare_selection(&selected, AnchorClocks::default()).unwrap();
    assert!(comparison.passed());
    assert!(comparison.time_validations.is_empty());
    let owner = policy::request_contract::RequestContracts::default();
    let (delivered, _) = translate_selection(&owner, "case", &selected, clocks()).unwrap();
    assert_eq!(delivered, selected.source);
    let different = temporal_selection(
        selected.source.clone(),
        json!("1970-01-01 00:00:01"),
        Temporal::Datetime,
    )
    .unwrap();
    assert!(!compare_selection(&different, clocks()).unwrap().passed());
}
