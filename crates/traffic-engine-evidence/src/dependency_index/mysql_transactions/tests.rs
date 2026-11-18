use super::*;
use serde_json::json;

fn file(path: &str, events: &[(u64, u16, u16)]) -> SourceFile {
    SourceFile {
        path: path.into(), stamp: FileStamp { size:0,device:0,inode:0,modified:(0,0),changed:(0,0) },
        sha256:String::new(), records:events.iter().map(|(seq,before,after)| IndexedMysqlRecord {
            location:super::super::RecordLocation { line:*seq as usize,offset:0,length:0,sha256:String::new() },
            summary:json!({"connection_id":"connection","query_sequence":seq,"server_status_before":before,
                "server_status_after":after,"target_host":"db.test","target_port":3306,"database":"app","username":"writer"}),
        }).collect(),
    }
}

#[test]
fn transaction_facts_join_global_prefix_and_case_commit_without_inventing_case_ownership() {
    let files = [
        file("apis/release/case/dependencies.jsonl", &[(411, 1, 0)]),
        file(
            "global-dependencies.jsonl",
            &[
                (405, 0, 1),
                (406, 1, 1),
                (407, 1, 1),
                (408, 1, 1),
                (409, 1, 1),
                (410, 1, 1),
            ],
        ),
    ];
    let (transactions, ambiguous) = intervals(&files);
    assert_eq!(ambiguous, 0);
    assert_eq!(transactions.len(), 1);
    let transaction = &transactions[0];
    assert!(transaction.known_start && transaction.closed);
    assert_eq!(transaction.members.len(), 7);
    assert_eq!(transaction.members.last().unwrap().file, 0);
}

#[test]
fn gaps_and_changed_resources_keep_the_prefix_unknown() {
    for changed in [false, true] {
        let mut source = file(
            "case/dependencies.jsonl",
            &[(1, 0, 1), (2, 1, 1), (3, 1, 0)],
        );
        if changed {
            source.records[1].summary["database"] = "other".into();
        } else {
            source.records[1].summary["query_sequence"] = 9.into();
        }
        let (transactions, _) = intervals(&[source]);
        assert!(!transactions.iter().any(|t| t.known_start && t.closed));
    }
}

#[test]
fn duplicated_wire_identity_cannot_prove_a_transaction() {
    let source = file("case/dependencies.jsonl", &[(1, 0, 1), (2, 1, 0)]);
    let (transactions, ambiguous) = intervals(&[source.clone(), source]);
    assert!(transactions.is_empty());
    assert_eq!(ambiguous, 1);
}

#[test]
fn recorder_and_legacy_metadata_preserve_non_sql_status_continuity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dependencies.jsonl");
    let events = [
        (1, Some("SELECT 1"), 0, 1),
        (2, None, 1, 1),
        (3, Some("COMMIT"), 1, 0),
    ];
    let raw: String = events
        .into_iter()
        .map(|(seq, sql, before, after)| {
            json!({"event_type":"mysql_exchange","connection_id":"connection","query_sequence":seq,
            "command":if sql.is_some() {"COM_QUERY"} else {"COM_PING"}, "sql":sql,
            "target_host":"db.test","target_port":3306,"database":"app","username":"writer",
            "server_status_before":before,"response":{"server_status":after,"rows":["private"]}})
            .to_string()
                + "\n"
        })
        .collect();
    std::fs::write(&path, raw).unwrap();
    let recorder = store::load_file(&path).unwrap();
    assert_eq!(recorder.records("mysql").len(), 3);
    let mut old = recorder.clone();
    old.indexes.remove("mysql");
    let legacy = super::super::mysql::extend(&path, old).unwrap();
    assert_eq!(
        serde_json::to_value(recorder.mysql_records()).unwrap(),
        serde_json::to_value(legacy.mysql_records()).unwrap()
    );
    let encoded = serde_json::to_string(&legacy.mysql_records()).unwrap();
    assert!(!encoded.contains("private") && !encoded.contains("SELECT 1"));
}
