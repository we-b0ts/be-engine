use super::*;
use crate::policy::{CompiledPolicy, Surface};
use serde_json::json;

fn policy(native: bool, arrays: bool) -> CompiledPolicy {
    let mut fields = json!({
        "/createdAt":{"relative_time":"iso8601_naive"},
        "/updatedAt":{"relative_time":"iso8601_naive"}
    });
    if arrays {
        fields["/blocks/*/at"] = json!({"relative_time":"unix_seconds"});
    }
    let rules = if native {
        json!([{
            "id":"generated-context","match":{"resource":"db","operation":"COM_QUERY","sql":"UPDATE tasks SET payload=? WHERE id=7"},
            "effect":{"kind":"mysql_values","values":{"0":{"kind":"json","fields":{
                "/createdAt":{"field_ref":{"resource":"db","table":"rows","column":"payload","pointer":"/createdAt"},"clock_group":"generation"}
            }}}},
            "proof":{"source":"models.py:write","fact":"This statement explicitly preserves the generated clock relationship"}
        }])
    } else {
        json!([])
    };
    crate::policy::parse_and_compile_policy(&json!({
        "format":"traffic-policy/v2","resources":{"db":{
            "protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"worker",
            "proof":{"source":"models.py:json","fact":"The declared payload fields preserve generated or delivered stored times"},
            "tables":{"rows":{"tables":["tasks","jobs"],"fields":{"payload":{"codec":"json","fields":fields}}}}
        }},"rules":rules,
    }).to_string()).unwrap()
}

fn identity() -> ReplaySessionIdentity {
    ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: Some("worker".into()),
    }
}
fn data(created: &str, updated: &str) -> Value {
    json!({"createdAt":created,"updatedAt":updated,"stable":"kept"})
}
fn response(value: &Value) -> RecordedMysqlResponse {
    serde_json::from_value(json!({"status":"resultset","columns":[{
        "name":"payload_alias","database":"app","table":"tasks","column":"payload","family":"text","sql_type":"JSON"
    }],"rows":[[{"kind":"string","value":value.to_string()}]]})).unwrap()
}
fn pending(policy: &CompiledPolicy, response: &RecordedMysqlResponse) -> PreparedRead {
    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyResponse)
        .collect::<Vec<_>>();
    from_rules(
        "case",
        &identity(),
        Some("app"),
        response,
        Some("SELECT payload AS payload_alias FROM tasks WHERE id=7"),
        &rules,
        Some(source_completed()),
    )
    .unwrap()
    .unwrap()
}
fn source_completed() -> chrono::DateTime<Utc> {
    "2019-12-31T23:59:59Z".parse().unwrap()
}
fn delivered_at() -> chrono::DateTime<Utc> {
    "2025-12-31T23:59:59Z".parse().unwrap()
}
fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
        },
        ..Default::default()
    }
}
fn compare(
    policy: &CompiledPolicy,
    owner: &RequestContracts,
    case: &str,
    source: &str,
    target: &str,
) -> Comparison {
    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    policy::compare_mysql_contracts_with_time_copies(
        Some("app"),
        Some(source),
        None,
        Some(target),
        None,
        &rules,
        &policy.native.iter().collect::<Vec<_>>(),
        clocks(),
        Some(policy::MysqlTimeCopyProofs::runtime(
            owner,
            case,
            clocks().dependency,
        )),
    )
    .unwrap()
}
fn update(table: &str, value: &Value) -> String {
    format!("UPDATE {table} SET payload='{value}' WHERE id=7")
}

#[test]
fn delivered_historical_time_is_copied_across_new_sql_without_weakening_other_fields() {
    let compiled = policy(false, false);
    let owner = RequestContracts::default();
    let read = response(&data("2010-01-01T00:00:00", "2019-01-01T00:00:00"));
    let source_value = data("2010-01-01T00:00:00", "2020-01-01T00:00:01");
    let target_value = data("2010-01-01T00:00:00", "2026-01-01T00:00:01");
    let source = update("tasks", &source_value);
    let target = update("tasks", &target_value);
    assert!(
        !compare(&compiled, &owner, "case", &source, &target).passed(),
        "equal historical values need prior delivery provenance"
    );
    let prepared = pending(&compiled, &read);
    assert!(
        !compare(&compiled, &owner, "case", &source, &target).passed(),
        "preparing a response is not delivering it"
    );
    prepared
        .commit(
            &owner,
            Some("case"),
            &identity(),
            &read,
            Some("SELECT payload AS payload_alias FROM tasks WHERE id=7"),
            delivered_at(),
        )
        .unwrap();
    for (source, target) in [
        (source.clone(), target.clone()),
        (
            source.replace("2010-01-01T00:00:00", "2010-01-01T00:00:00.000"),
            target.clone(),
        ),
        (
            format!("INSERT INTO tasks(id,payload) VALUES(7,'{source_value}')"),
            format!("INSERT INTO tasks(id,payload) VALUES(7,'{target_value}')"),
        ),
        (
            format!(
                "UPDATE tasks SET state='active', payload='{source_value}' WHERE id=7 AND tenant='stable'"
            ),
            format!(
                "UPDATE tasks SET state='active', payload='{target_value}' WHERE id=7 AND tenant='stable'"
            ),
        ),
    ] {
        let result = compare(&compiled, &owner, "case", &source, &target);
        assert!(result.passed(), "{:?}", result.differences);
    }
    assert!(!compare(&compiled, &owner, "other-case", &source, &target).passed());
    assert!(
        !compare(
            &compiled,
            &owner,
            "case",
            &source.replace("tasks", "jobs"),
            &target.replace("tasks", "jobs")
        )
        .passed(),
        "provenance is a physical table identity, not a declaration family permission"
    );
    assert!(
        !compare(
            &compiled,
            &owner,
            "case",
            &source,
            &target.replace("2010-01-01T00:00:00", "2010-01-01T00:00:01")
        )
        .passed()
    );
    assert!(
        !compare(
            &compiled,
            &owner,
            "case",
            &source,
            &target.replace("kept", "changed")
        )
        .passed()
    );
    owner.begin_case("case");
    assert!(
        !compare(&compiled, &owner, "case", &source, &target).passed(),
        "new case attempts do not retain old deliveries"
    );
}

#[test]
fn explicit_native_generation_contract_remains_strict_after_a_schema_copy() {
    let compiled = policy(true, false);
    let owner = RequestContracts::default();
    let read = response(&data("2010-01-01T00:00:00", "2019-01-01T00:00:00"));
    pending(&compiled, &read)
        .commit(
            &owner,
            Some("case"),
            &identity(),
            &read,
            None,
            delivered_at(),
        )
        .unwrap();
    let source = update("tasks", &data("2010-01-01T00:00:00", "2020-01-01T00:00:01"));
    let target = update("tasks", &data("2010-01-01T00:00:00", "2026-01-01T00:00:01"));
    assert!(!compare(&compiled, &owner, "case", &source, &target).passed());
}

#[test]
fn unchanged_read_decodes_once_and_rewritten_arrays_have_indexed_leaf_pairing() {
    let compiled = policy(false, true);
    let owner = RequestContracts::default();
    let mut value = data("2010-01-01T00:00:00", "2019-01-01T00:00:00");
    value["blocks"] = json!(
        (0..2000)
            .map(|index| json!({"at":1_262_304_000_i64 + index}))
            .collect::<Vec<_>>()
    );
    let original = response(&value);
    let (prepared, source_decodes) =
        crate::value_codec::measured_decodes(|| pending(&compiled, &original));
    assert_eq!(source_decodes, 1);
    let (_, unchanged_decodes) = crate::value_codec::measured_decodes(|| {
        prepared
            .commit(
                &owner,
                Some("case"),
                &identity(),
                &original,
                None,
                delivered_at(),
            )
            .unwrap()
    });
    assert_eq!(unchanged_decodes, 0);
    for block in value["blocks"].as_array_mut().unwrap() {
        block["at"] = json!(block["at"].as_i64().unwrap() + 86_400);
    }
    let changed = response(&value);
    let (_, changed_decodes) = crate::value_codec::measured_decodes(|| {
        prepared
            .commit(
                &owner,
                Some("case"),
                &identity(),
                &changed,
                None,
                delivered_at(),
            )
            .unwrap()
    });
    assert_eq!(changed_decodes, 1);
}

#[test]
fn native_datetime_copies_preserve_the_instant_across_driver_fraction_spelling() {
    let compiled = crate::policy::parse_and_compile_policy(&json!({"format":"traffic-policy/v2","resources":{"db":{
        "protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"worker",
        "proof":{"source":"models.py:created","fact":"Stored creation time is copied from the delivered native SQL field"},
        "tables":{"tasks":{"fields":{"created_at":{"relative_time":"sql_datetime"}}}}
    }},"rules":[]}).to_string()).unwrap();
    let read: RecordedMysqlResponse = serde_json::from_value(json!({"status":"resultset","columns":[{
        "name":"created_at","database":"app","table":"tasks","column":"created_at","family":"datetime","sql_type":"DATETIME"
    }],"rows":[[{"kind":"datetime","value":"2010-01-01 00:00:00.000"}]]})).unwrap();
    let owner = RequestContracts::default();
    let rules = compiled
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyResponse)
        .collect::<Vec<_>>();
    from_rules(
        "case",
        &identity(),
        Some("app"),
        &read,
        None,
        &rules,
        Some(source_completed()),
    )
    .unwrap()
    .unwrap()
    .commit(
        &owner,
        Some("case"),
        &identity(),
        &read,
        None,
        delivered_at(),
    )
    .unwrap();
    let source = "UPDATE tasks SET created_at='2010-01-01 00:00:00.000000' WHERE id=7";
    let target = "UPDATE tasks SET created_at='2010-01-01 00:00:00' WHERE id=7";
    let result = compare(&compiled, &owner, "case", source, target);
    assert!(result.passed(), "{:?}", result.differences);
    assert!(
        !compare(
            &compiled,
            &owner,
            "case",
            source,
            &target.replace("00:00:00'", "00:00:01'")
        )
        .passed()
    );
}

#[test]
fn protected_delivered_witnesses_feed_the_same_pure_field_provenance() {
    use crate::value_contract::time_copies::{TimeCopyRecord, TimeCopyStore};
    let compiled = policy(false, false);
    let read = response(&data("2010-01-01T00:00:00.000", "2019-01-01T00:00:00"));
    let event = json!({"command":"COM_QUERY","sql":"SELECT payload AS payload_alias FROM tasks WHERE id=7",
        "database":"app","timestamp":"2019-12-31T23:59:59Z","duration_ms":0,"response":read});
    let source_read = super::super::source_witness(&event, Surface::DependencyResponse).unwrap();
    let mut delivered: Value = serde_json::from_slice(&source_read).unwrap();
    delivered["response_delivered_at"] = json!("2025-12-31T23:59:59Z");
    delivered["request"]["request_started_at"] = json!("2025-12-31T23:59:59Z");
    let resource = compiled.rules[0].rule.selector.resource.as_ref().unwrap();
    let read_rules = compiled
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyResponse)
        .collect::<Vec<_>>();
    let mut records = Vec::new();
    let captured = delivered_witness_time_copies(
        &source_read,
        &serde_json::to_vec(&delivered).unwrap(),
        &read_rules,
        resource,
        Some("app"),
        &mut |source: TimeCopyPosition<'_>,
              target: TimeCopyPosition<'_>,
              source_pattern: &str,
              target_pattern: &str,
              source_value: &Value,
              target_value: &Value,
              time: &crate::policy::TimeContract| {
            records.push(TimeCopyRecord::new_time(
                time,
                source,
                target,
                source_pattern,
                target_pattern,
                source_value,
                target_value,
            )?);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(captured, 2);
    let mut store = TimeCopyStore::default();
    store.set_record_clocks(crate::value_contract::time::ClockPair {
        source: Some(source_completed()),
        target: Some(delivered_at()),
    });
    store.record_batch("case", records).unwrap();
    store.set_lookup_clocks(clocks().dependency);
    let source = serde_json::to_vec(
        &json!({"command":"COM_QUERY","request_started_at":"2020-01-01T00:00:00Z",
        "sql":update("tasks", &data("2010-01-01T00:00:00", "2020-01-01T00:00:01"))}),
    )
    .unwrap();
    let target = serde_json::to_vec(
        &json!({"command":"COM_QUERY","request_started_at":"2026-01-01T00:00:00Z",
        "sql":update("tasks", &data("2010-01-01T00:00:00", "2026-01-01T00:00:01"))}),
    )
    .unwrap();
    let writes = compiled
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyRequest)
        .collect::<Vec<_>>();
    assert!(
        !super::super::validate_contract_candidate(
            Some("app"),
            &source,
            &target,
            &writes,
            &[],
            clocks()
        )
        .unwrap()
        .unwrap()
        .passed()
    );
    let copied = super::super::validate_contract_candidate_with_time_copies(
        Some("app"),
        &source,
        &target,
        &writes,
        &[],
        clocks(),
        &store,
        "case",
    )
    .unwrap()
    .unwrap();
    assert!(copied.passed(), "{:?}", copied.differences);
}

#[test]
fn selected_read_provenance_is_bounded_across_rows_and_columns() {
    let compiled = policy(false, true);
    let mut value = data("2010-01-01T00:00:00", "2019-01-01T00:00:00");
    value["blocks"] = json!(
        (0..2000)
            .map(|index| json!({"at":1_262_304_000_i64 + index}))
            .collect::<Vec<_>>()
    );
    let mut read = response(&value);
    read.rows = vec![read.rows[0].clone(); 3];
    let rules = compiled
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == Surface::DependencyResponse)
        .collect::<Vec<_>>();
    let error = from_rules(
        "case",
        &identity(),
        Some("app"),
        &read,
        None,
        &rules,
        Some(source_completed()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("4096 selected leaves"));
}

#[test]
fn copies_require_the_read_to_complete_before_both_write_requests() {
    let compiled = policy(false, false);
    let read = response(&data("2010-01-01T00:00:00", "2019-01-01T00:00:00"));
    let source = update("tasks", &data("2010-01-01T00:00:00", "2020-01-01T00:00:01"));
    let target = update("tasks", &data("2010-01-01T00:00:00", "2026-01-01T00:00:01"));
    for (source_complete, target_complete, allowed) in [
        (source_completed(), delivered_at(), true),
        (
            clocks().dependency.source.unwrap() + chrono::Duration::seconds(1),
            delivered_at(),
            false,
        ),
        (
            source_completed(),
            clocks().dependency.target.unwrap() + chrono::Duration::seconds(1),
            false,
        ),
    ] {
        let owner = RequestContracts::default();
        let mut prepared = pending(&compiled, &read);
        prepared.source_completed_at = Some(source_complete);
        prepared
            .commit(
                &owner,
                Some("case"),
                &identity(),
                &read,
                None,
                target_complete,
            )
            .unwrap();
        let result = compare(&compiled, &owner, "case", &source, &target);
        assert_eq!(
            result.passed(),
            allowed,
            "Source {source_complete}; Target {target_complete}: {:?}",
            result.differences
        );
    }
    let rules = compiled.rules.iter().collect::<Vec<_>>();
    assert!(
        from_rules("case", &identity(), Some("app"), &read, None, &rules, None)
            .unwrap()
            .is_none(),
        "missing immutable Source read completion cannot become provenance"
    );
}
