use super::*;
use serde_json::json;

const A: &str = "00000000-0000-4000-8000-000000000001";
const X: &str = "00000000-0000-4000-8000-000000000002";
const Y: &str = "00000000-0000-4000-8000-000000000003";

#[test]
fn unselected_json_scalars_are_ordinary_sql_strings_but_objects_keep_their_codec() {
    let policy = policy();
    let identity = identity();
    let record = record("SELECT id FROM users");
    let context = RequestContext::new(&policy, Metadata::default(), &identity, &record);
    for value in ["801", "true", "null", "\"a\""] {
        let token = crate::mysql::sql::Token::Bytes(value.as_bytes().to_vec());
        assert!(
            context
                .select(&token, &token, None, 0, clocks())
                .unwrap()
                .is_none()
        );
    }
    let source = crate::mysql::sql::Token::Bytes(br#"{"stable":7}"#.to_vec());
    let target = crate::mysql::sql::Token::Bytes(br#"{ "stable" : 7 }"#.to_vec());
    let selected = context
        .select(&source, &target, None, 0, clocks())
        .unwrap()
        .unwrap();
    assert!(compare_selection(&selected, clocks()).unwrap().passed());
}

#[test]
fn protected_unselected_numeric_string_predicates_keep_native_permutation_proof() {
    let policy = policy();
    let clocks = clocks();
    let source = serde_json::to_vec(
        &json!({"command":"COM_QUERY","request_started_at":clocks.dependency.source,
        "sql":"SELECT id FROM users WHERE code IN ('801','388')","params":null}),
    )
    .unwrap();
    let resource = serde_json::from_value(
        json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app"}),
    )
    .unwrap();
    for (value, passes) in [("801", true), ("802", false)] {
        let target = serde_json::to_vec(&json!({"command":"COM_STMT_EXECUTE","request_started_at":clocks.dependency.target,
            "sql":"SELECT id FROM users WHERE code IN (?,?)","params":[{"kind":"string","value":"388"},{"kind":"string","value":value}]})).unwrap();
        let result = validate_witness_with_time_copies(
            Some("app"),
            &source,
            &target,
            Surface::DependencyRequest,
            &policy,
            clocks,
            &resource,
            &crate::value_contract::time_copies::TimeCopyStore::default(),
            "case",
            &Metadata::default(),
        );
        assert_eq!(result.is_ok_and(|result| result.passed()), passes);
    }
}

fn policy() -> CompiledPolicy {
    crate::policy::parse_and_compile_policy(&json!({
        "format":"traffic-policy/v3",
        "json":{"fields":{"/item_id":{"kind":"identity","formats":["uuid"]}}},
        "mysql":{"tables":{"tasks":{"pattern":"tasks","fields":{"id":{"kind":"identity","formats":["uuid"]}}}}}
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
fn mysql_formats_apply_across_databases_while_physical_pairing_stays_strict() {
    let policy = policy();
    let source = record(&format!("UPDATE other.tasks SET id='{A}'"));
    assert!(
        compare(
            &policy,
            Metadata::default(),
            &source,
            &format!("UPDATE other.tasks SET id='{X}'")
        )
        .unwrap()
        .passed()
    );
    assert!(
        compare(
            &policy,
            Metadata::default(),
            &source,
            &format!("UPDATE foreign_db.tasks SET id='{X}'")
        )
        .is_err(),
        "a shared scalar format cannot change the physical SQL database"
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
        .unwrap()
        .passed()
    );
    target.columns[0].database = Some("foreign_db".into());
    assert!(
        compare_response(
            &policy,
            &read.response,
            &target,
            None,
            Some("app"),
            clocks()
        )
        .is_err(),
        "time inference cannot change the physical result-column origin"
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

#[test]
fn text_insert_matches_prepared_generated_fields() {
    let document = json!({
        "format":"traffic-policy/v3",
        "json":{"fields":{"/created_at":{"kind":"time","formats":["sql_datetime"]}}},
        "mysql":{"tables":{"tasks":{"pattern":"tasks_*","fields":{"name":{"kind":"identity","formats":[{"prefix":"task-pending-","hex":32}]}}}}}
    });
    let mut metadata = Metadata::default();
    for name in ["created_at", "updated_at"] {
        let mut read = temporal_record("DATETIME", "datetime", "2020-01-01 08:00:01.123456");
        read.sql = Some(format!("SELECT {name} FROM tasks_0438"));
        read.response.columns[0].name = name.into();
        read.response.columns[0].column = Some(name.into());
        read.response.columns[0].table = Some("tasks_0438".into());
        metadata.observe(&identity(), &read);
    }
    let source = record(
        "INSERT INTO tasks_0438 (id, user_id, kind, name, namespace, json, is_active, created_at, updated_at, project_id, client_origin, is_group_chat) VALUES (123, 6582, 'Task', 'task-pending-1348ab66fd8a4c7caf24849d5a31f63e', 'default', '{\"kind\": \"Task\"}', 1, '2020-01-01 08:00:01.123456', '2020-01-01 08:00:01.123462', 2571, 'frontend', 0)",
    );
    let params: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
        {"kind":"integer","value":123}, {"kind":"integer","value":6582},
        {"kind":"string","value":"Task"},
        {"kind":"string","value":"task-pending-62a63f0725a07ec23778aac6a11b9962"},
        {"kind":"string","value":"default"}, {"kind":"string","value":"{\"kind\": \"Task\"}"},
        {"kind":"integer","value":1},
        {"kind":"string","value":"2026-01-01 08:00:01.234567"},
        {"kind":"string","value":"2026-01-01 08:00:01.234567"},
        {"kind":"integer","value":2571}, {"kind":"string","value":"frontend"},
        {"kind":"integer","value":0}
    ]))
    .unwrap();
    let identity = identity();
    for declared in [false, true] {
        let mut document = document.clone();
        if declared {
            for name in ["created_at", "updated_at"] {
                document["mysql"]["tables"]["tasks"]["fields"][name] =
                    json!({"kind":"time","formats":["sql_datetime"]});
            }
        }
        let policy = crate::policy::parse_and_compile_policy(&document.to_string()).unwrap();
        let context = RequestContext::new(&policy, metadata.clone(), &identity, &source);
        let compare = |params: &[RecordedMysqlValue]| {
            policy::compare_mysql_with_automatic(
                Some("app"),
                source.sql.as_deref(),
                None,
                Some(
                    "INSERT INTO `tasks_0438` (id, user_id, kind, name, namespace, json, is_active, created_at, updated_at, project_id, client_origin, is_group_chat) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ),
                Some(params),
                &[],
                &[],
                clocks(),
                None,
                &context,
            )
        };
        let result = compare(&params).unwrap();
        assert!(
            result.passed(),
            "declared={declared}: {:?}",
            result.differences
        );
        for (index, value) in [
            (3, json!("task-pending-invalid")),
            (7, json!("2026-01-01 08:01:01.234567")),
            (9, json!(9999)),
        ] {
            let mut invalid = params.clone();
            invalid[index].value = Some(value);
            assert!(!compare(&invalid).is_ok_and(|comparison| comparison.passed()));
        }
    }
}

#[test]
fn native_result_times_do_not_relate_distinct_columns_or_rows() {
    let policy = policy();
    let mut source = temporal_record("DATETIME", "datetime", "2020-01-01 08:00:01.123456");
    let mut column = source.response.columns[0].clone();
    column.name = "updated_at".into();
    column.column = Some("updated_at".into());
    source.response.columns.push(column);
    source.response.rows[0].push(
        serde_json::from_value(json!({"kind":"datetime","value":"2020-01-01 08:00:01.123462"}))
            .unwrap(),
    );
    source.response.rows.push(source.response.rows[0].clone());
    source.response.rows[1][0].value = Some(json!("2020-01-01 08:00:01.123480"));
    let mut target = source.response.clone();
    for row in &mut target.rows {
        for value in row {
            value.value = Some(json!("2026-01-01 08:00:01.234567"));
        }
    }
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
    target.rows[1][0].value = Some(json!("2026-01-01 08:01:01.234567"));
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
}

#[test]
fn explicit_sql_clock_group_still_checks_the_column_relationship() {
    let document = json!({"format":"traffic-policy/v3","rules":[{
        "id":"linked-times",
        "match":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":"INSERT INTO tasks(created_at,updated_at) VALUES(?,?)"},
        "effect":{"kind":"mysql_values","values":{
            "0":{"relative_time":"sql_datetime","utc_offset":"+00:00","clock_group":"task-create"},
            "1":{"relative_time":"sql_datetime","utc_offset":"+00:00","clock_group":"task-create"}
        }},
        "proof":{"source":"tasks.py:create","fact":"Both fields retain the same clock shift"}
    }]});
    let policy = crate::policy::parse_and_compile_policy(&document.to_string()).unwrap();
    let identity = identity();
    let source = record(
        "INSERT INTO tasks(created_at,updated_at) VALUES('2020-01-01 08:00:01.123456','2020-01-01 08:00:01.123462')",
    );
    let context = RequestContext::new(&policy, Metadata::default(), &identity, &source);
    let check = |sql: &str| {
        policy::compare_mysql_with_automatic(
            Some("app"),
            source.sql.as_deref(),
            None,
            Some(sql),
            None,
            &[],
            &policy.native.iter().collect::<Vec<_>>(),
            clocks(),
            None,
            &context,
        )
        .unwrap()
    };
    assert!(check("INSERT INTO tasks(created_at,updated_at) VALUES('2026-01-01 08:00:01.234567','2026-01-01 08:00:01.234573')").passed());
    assert!(!check("INSERT INTO tasks(created_at,updated_at) VALUES('2026-01-01 08:00:01.234567','2026-01-01 08:00:01.234567')").passed());
}
