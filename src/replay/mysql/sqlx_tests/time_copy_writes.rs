//! Cross-carrier delivered time pairs retain their original clock at SQL writes.
use super::*;
use crate::policy::{CompiledPolicy, RedisContainer};
use crate::replay::policy::{MysqlTimeCopyProofs, request_contract::RequestContracts};
use crate::value_contract::{
    json::AnchorClocks,
    time::ClockPair,
    time_copies::{TimeCopyPosition, TimeCopyRecord, TimeCopyStore},
};

fn clock(source: i64, target: i64) -> ClockPair {
    ClockPair {
        source: chrono::DateTime::from_timestamp(source, 0),
        target: chrono::DateTime::from_timestamp(target, 0),
    }
}

fn policy() -> CompiledPolicy {
    crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /timestamp: {kind: time, formats: [unix_seconds]}
    /blocks/*/timestamp: {kind: time, formats: [unix_seconds]}
    /created_at: {kind: time, formats: [unix_seconds]}
"#,
    )
    .unwrap()
}

fn record(policy: &CompiledPolicy) -> TimeCopyRecord {
    let time = policy.global_json.as_ref().unwrap().fields["/timestamp"]
        .select_contract_with_clock(&json!(1000), clock(1000, 2000).source)
        .unwrap()
        .time()
        .unwrap();
    let position = TimeCopyPosition::Redis {
        host: "cache.test",
        port: 6379,
        database: 0,
        key: b"blocks:1",
        container: RedisContainer::String,
        hash_field: None,
    };
    TimeCopyRecord::new_time(
        &time,
        position,
        position,
        "/timestamp",
        "/timestamp",
        &json!(1000),
        &json!(2000),
    )
    .unwrap()
}

fn store(policy: &CompiledPolicy, delivery: ClockPair) -> TimeCopyStore {
    let mut store = TimeCopyStore::default();
    store.set_record_clocks(delivery);
    store.record_batch("case", vec![record(policy)]).unwrap();
    store.set_lookup_clocks(clock(1060, 2001));
    store
}

fn compare(
    policy: &CompiledPolicy,
    copies: Option<MysqlTimeCopyProofs<'_>>,
    target: Value,
    sql: &str,
    clocks: ClockPair,
) -> bool {
    // Source did another minute of work before this write, while Target did
    // less work. The copied timestamp must not inherit either duration.
    let source = json!({"blocks":[{"timestamp":1000}],"created_at":1060,"stable":7});
    let source_sql = format!("UPDATE tasks SET result='{source}' WHERE id=7");
    let mut source_record = exchange(&source_sql, json!({"status":"ok"}));
    source_record["timestamp"] = json!(clock(1060, 2001).source.unwrap());
    let source_record: RecordedMysqlExchange = serde_json::from_value(source_record).unwrap();
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("appdb".into()),
        username: Some("root".into()),
    };
    let context = contracts::automatic::RequestContext::new(
        policy,
        Default::default(),
        &identity,
        &source_record,
    );
    let params: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
        {"kind":"string","value":target.to_string()}, {"kind":"integer","value":7}
    ]))
    .unwrap();
    crate::replay::policy::compare_mysql_with_automatic(
        Some("appdb"),
        Some(&source_sql),
        None,
        Some(sql),
        Some(&params),
        &[],
        &[],
        AnchorClocks {
            dependency: clocks,
            ..Default::default()
        },
        copies,
        &context,
    )
    .is_ok_and(|comparison| comparison.passed())
}

const SQL: &str = "UPDATE tasks SET result=? WHERE id=?";
fn target() -> Value {
    json!({"blocks":[{"timestamp":2000}],"created_at":2001,"stable":7})
}

#[test]
fn redis_delivered_timestamp_copy_does_not_acquire_the_completion_sql_clock() {
    let policy = policy();
    let store = store(&policy, clock(1000, 2000));
    assert!(!compare(&policy, None, target(), SQL, clock(1060, 2001)));
    assert!(compare(
        &policy,
        Some(MysqlTimeCopyProofs::stored(&store, "case")),
        target(),
        SQL,
        clock(1060, 2001),
    ));
    let owner = RequestContracts::default();
    owner
        .record_time_copies("case", vec![record(&policy)], clock(1000, 2000))
        .unwrap();
    assert!(compare(
        &policy,
        Some(MysqlTimeCopyProofs::runtime(
            &owner,
            "case",
            clock(1060, 2001)
        )),
        target(),
        SQL,
        clock(1060, 2001),
    ));
}

#[test]
fn delivered_copies_do_not_accept_other_values_types_local_times_or_sql() {
    let policy = policy();
    let store = store(&policy, clock(1000, 2000));
    for (pointer, changed) in [
        ("/blocks/0/timestamp", json!(2001)),
        ("/blocks/0/timestamp", json!("2000")),
        ("/created_at", json!(2060)),
        ("/stable", json!(8)),
    ] {
        let mut target = target();
        *target.pointer_mut(pointer).unwrap() = changed;
        assert!(
            !compare(
                &policy,
                Some(MysqlTimeCopyProofs::stored(&store, "case")),
                target,
                SQL,
                clock(1060, 2001),
            ),
            "{pointer}"
        );
    }
    assert!(!compare(
        &policy,
        Some(MysqlTimeCopyProofs::stored(&store, "case")),
        target(),
        "UPDATE tasks SET result=? WHERE other_id=?",
        clock(1060, 2001),
    ));
}

#[test]
fn copied_sql_times_require_the_same_live_case_and_successful_past_deliveries() {
    let policy = policy();
    let mut store = store(&policy, clock(1000, 2000));
    assert!(!compare(
        &policy,
        Some(MysqlTimeCopyProofs::stored(&store, "another-case")),
        target(),
        SQL,
        clock(1060, 2001),
    ));
    store.begin_case("case");
    assert!(!compare(
        &policy,
        Some(MysqlTimeCopyProofs::stored(&store, "case")),
        target(),
        SQL,
        clock(1060, 2001),
    ));
    for delivery in [clock(1061, 2000), clock(1000, 2002), ClockPair::default()] {
        let store = self::store(&policy, delivery);
        assert!(!compare(
            &policy,
            Some(MysqlTimeCopyProofs::stored(&store, "case")),
            target(),
            SQL,
            clock(1060, 2001),
        ));
        let owner = RequestContracts::default();
        owner
            .record_time_copies("case", vec![record(&policy)], delivery)
            .unwrap();
        assert!(!compare(
            &policy,
            Some(MysqlTimeCopyProofs::runtime(
                &owner,
                "case",
                clock(1060, 2001)
            )),
            target(),
            SQL,
            clock(1060, 2001),
        ));
    }
}

#[test]
fn runtime_copy_causality_uses_the_actual_sql_request_observation() {
    let policy = policy();
    let owner = RequestContracts::default();
    owner
        .record_time_copies("case", vec![record(&policy)], clock(1000, 2000))
        .unwrap();
    // The supplied comparison anchors cannot make a future delivery causal.
    for observed in [clock(999, 2001), clock(1060, 1999), ClockPair::default()] {
        assert!(!compare(
            &policy,
            Some(MysqlTimeCopyProofs::runtime(&owner, "case", observed)),
            target(),
            SQL,
            clock(1060, 2001),
        ));
    }
    assert!(!compare(
        &policy,
        Some(MysqlTimeCopyProofs::runtime(
            &owner,
            "another-case",
            clock(1060, 2001)
        )),
        target(),
        SQL,
        clock(1060, 2001),
    ));
    owner.clear_time_copies("case");
    assert!(!compare(
        &policy,
        Some(MysqlTimeCopyProofs::runtime(
            &owner,
            "case",
            clock(1060, 2001)
        )),
        target(),
        SQL,
        clock(1060, 2001),
    ));
}
