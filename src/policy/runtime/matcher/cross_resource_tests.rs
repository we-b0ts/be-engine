//! The same format declaration and Case identity state span native carriers.
use super::*;
use crate::protocols::replay::mysql::RecordedMysqlExchange;
use crate::replay::ReplayCaseStatus;
use serde_json::json;

const A: &str = "11111111-1111-4111-8111-111111111111";
const X: &str = "22222222-2222-4222-8222-222222222222";
const Y: &str = "33333333-3333-4333-8333-333333333333";

fn runtime() -> (tempfile::TempDir, ReplayPolicyRuntime) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp.path().join("case");
    fs::create_dir(&case).unwrap();
    fs::write(
        case.join("request.json"),
        json!({
            "method":"POST", "uri":"/write", "timestamp":"1970-01-01T00:16:40Z"
        })
        .to_string(),
    )
    .unwrap();
    fs::write(case.join("expected-response.json"), "{}").unwrap();
    fs::write(case.join("dependencies.jsonl"), "").unwrap();
    let path = temp.path().join("policy.yaml");
    fs::write(&path, "format: traffic-policy/v3\njson:\n  fields:\n    /item_id: {kind: identity, formats: [uuid]}\n    /created_at: {kind: time, formats: [unix_seconds]}\n").unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dependencies_path: case.join("dependencies.jsonl"),
            dir: case,
            status: ReplayCaseStatus::Pending,
        },
    )]);
    let runtime = ReplayPolicyRuntime::load(&path, &cases).unwrap();
    (temp, runtime)
}

fn payload(id: &str, time: i64, stable: i64) -> Vec<u8> {
    serde_json::to_vec(&json!({"item_id":id,"created_at":time,"stable":stable})).unwrap()
}

#[test]
fn one_global_time_identity_contract_and_bijection_are_shared_by_redis_and_mysql() {
    let (_temp, runtime) = runtime();
    let owner = &runtime.request_contracts;
    let source = payload(A, 1000, 7);
    let target = payload(X, 2000, 7);
    let cache = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let redis = crate::policy::runtime::request_contract::RedisRequestContext {
        case: "case",
        target: &cache,
        database: 0,
        username: None,
        command: "SET",
        recorded_at: DateTime::from_timestamp(1000, 0),
        actual_at: DateTime::from_timestamp(2000, 0),
        connection_id: Some(uuid::Uuid::new_v4()),
        sequence: Some(1),
        observation_id: Some(uuid::Uuid::new_v4()),
    };
    let before = vec![b"session".to_vec(), source.clone()];
    let after = vec![b"session".to_vec(), target.clone()];
    let decision = owner
        .preview_redis_context(&redis, &before, &after)
        .unwrap()
        .unwrap();
    owner.commit(decision).unwrap();

    let source_sql = format!(
        "UPDATE entries SET payload='{}' WHERE id=7",
        std::str::from_utf8(&source).unwrap()
    );
    let record: RecordedMysqlExchange = serde_json::from_value(json!({
        "command":"COM_QUERY","sql":source_sql,"database":"app",
        "timestamp":"1970-01-01T00:16:40Z","duration_ms":0,"response":{"status":"ok"}
    }))
    .unwrap();
    let mysql = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: "db.test".into(),
            port: 3306,
        }),
        database: Some("app".into()),
        username: None,
    };
    for (value, passes) in [
        (target, true),
        (payload(Y, 2000, 7), false),
        (payload(X, 1500, 7), false),
        (payload(X, 2000, 8), false),
    ] {
        let sql = format!(
            "UPDATE entries SET payload='{}' WHERE id=7",
            std::str::from_utf8(&value).unwrap()
        );
        let sql_result = owner
            .preview_mysql_values(
                Some("case"),
                &mysql,
                &record,
                "COM_QUERY",
                Some(&sql),
                None,
                DateTime::from_timestamp(2000, 0).unwrap(),
                &runtime,
            )
            .expect("a native SQL JSON value is selected by the global field contract");
        assert_eq!(sql_result.is_ok(), passes, "MySQL: {sql_result:?}");
        let params: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
            {"kind":"string","value":std::str::from_utf8(&value).unwrap()}
        ]))
        .unwrap();
        let args_result = owner
            .preview_mysql_values(
                Some("case"),
                &mysql,
                &record,
                "COM_STMT_EXECUTE",
                Some("UPDATE entries SET payload=? WHERE id=7"),
                Some(&params),
                DateTime::from_timestamp(2000, 0).unwrap(),
                &runtime,
            )
            .expect("SQL args reuse the same logical JSON contract");
        assert_eq!(args_result.is_ok(), passes, "MySQL args: {args_result:?}");
        let redis_result = owner
            .preview_redis_context(&redis, &before, &[b"session".to_vec(), value])
            .unwrap();
        assert_eq!(redis_result.is_ok(), passes, "Redis: {redis_result:?}");
    }
}
