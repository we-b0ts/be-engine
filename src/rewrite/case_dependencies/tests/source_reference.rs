use super::*;
use serde_json::json;

fn fixture(
    protocol: &str,
) -> (
    tempfile::TempDir,
    RewriteCaseDependenciesOptions,
    uuid::Uuid,
) {
    let temp = tempfile::tempdir().unwrap();
    let case = temp
        .path()
        .join(".traffic-e2e/local/artifacts/run/api/case-a");
    std::fs::create_dir_all(&case).unwrap();
    let connection = uuid::Uuid::new_v4();
    let events = (0..8).map(|sequence| {
        if protocol == "redis" {
            json!({"event_type":"redis_exchange", "target_host":"cache.test", "target_port":6379,
                "connection_id":connection,"sequence":sequence,"command":"GET",
                "args":[{"encoding":"utf8","data":format!("task:streaming:{sequence}"),"original_len":format!("task:streaming:{sequence}").len(),"truncated":false}],
                "response_kind":"bulk_string","response":{"encoding":"utf8","data":"$-1\r\n","original_len":5,"truncated":false},"outcome":"response"})
        } else {
            json!({"event_type":"mysql_exchange", "target_host":"db.test", "target_port":3306,
                "connection_id":connection,"query_sequence":sequence,"command":"COM_QUERY",
                "sql":format!("SELECT id FROM tasks WHERE id={sequence}"),"database":"app",
                "response":{"status":"resultset","row_count":0,"rows":[],"columns":[]},"outcome":"response"})
        }
    }).map(|event|event.to_string()).collect::<Vec<_>>().join("\n");
    std::fs::write(case.join("dependencies.jsonl"), events).unwrap();
    let mut options = RewriteCaseDependenciesOptions {
        target_root: temp.path().into(),
        case_dir: case,
        target_id: None,
    };
    let summary = serde_json::to_value(query(options.clone()).unwrap()).unwrap();
    options.target_id = Some(summary["targets"][0]["target_id"].as_str().unwrap().into());
    (temp, options, connection)
}

#[test]
fn exact_source_reference_reads_a_redis_blocker_outside_the_representative_window() {
    let (_temp, options, connection) = fixture("redis");
    let file = options.case_dir.join("dependencies.jsonl");
    let before = std::fs::read(&file).unwrap();
    let ordinary = serde_json::to_value(query(options.clone()).unwrap()).unwrap();
    assert_eq!(
        ordinary["operations"][0]["representative_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(!ordinary.to_string().contains("task:streaming:7"));
    assert!(
        ordinary["exchange_query"]["argv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg == "--connection-id")
    );
    let exact = serde_json::to_value(query_exchange(options, connection, 7).unwrap()).unwrap();
    assert_eq!(exact["event_count"], 1);
    assert_eq!(
        exact["source_reference"]["connection_id"],
        connection.to_string()
    );
    assert_eq!(exact["source_reference"]["sequence"], 7);
    assert_eq!(
        exact["operations"][0]["representative_exchanges"][0]["args"][0]["data"],
        "task:streaming:7"
    );
    assert_eq!(std::fs::read(file).unwrap(), before);
}

#[test]
fn mysql_source_references_use_query_sequence_and_reject_missing_or_ambiguous_matches() {
    let (_temp, options, connection) = fixture("mysql");
    let exact =
        serde_json::to_value(query_exchange(options.clone(), connection, 0).unwrap()).unwrap();
    assert_eq!(exact["event_count"], 1);
    assert_eq!(
        exact["operations"][0]["representative_exchanges"][0]["query_sequence"],
        0
    );
    assert!(query_exchange(options.clone(), uuid::Uuid::new_v4(), 0).is_err());
    assert!(query_exchange(options.clone(), connection, 99).is_err());
    let mut no_target = options.clone();
    no_target.target_id = None;
    assert!(query_exchange(no_target, connection, 0).is_err());
    let file = options.case_dir.join("dependencies.jsonl");
    let bytes = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, format!("{bytes}\n{}", bytes.lines().next().unwrap())).unwrap();
    let error = query_exchange(options, connection, 0)
        .unwrap_err()
        .to_string();
    assert!(error.contains("resolved to 2 exchanges"), "{error}");
}
