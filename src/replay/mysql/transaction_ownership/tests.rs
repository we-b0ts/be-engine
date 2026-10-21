use super::*;
use serde_json::{Value, json};
use std::fs;

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    connection: Uuid,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("run");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("recording-run.json"),
            r#"{"status":"completed","run_id":"transaction-global"}"#,
        )
        .unwrap();
        Self {
            _temporary: temporary,
            root,
            connection: Uuid::new_v4(),
        }
    }

    fn write(&self, relative: &str, events: &[Value]) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let raw = events
            .iter()
            .map(|value| value.to_string() + "\n")
            .collect::<String>();
        fs::write(path, raw).unwrap();
    }

    fn statement(&self, sequence: u64, sql: &str, before: u16, after: u16) -> Value {
        json!({"event_type":"mysql_exchange","command":"COM_QUERY","sql":sql,
            "connection_id":self.connection,"query_sequence":sequence,
            "target_host":"db.test","target_port":3306,"database":"app","username":"writer",
            "server_status_before":before,"outcome":"response","parse_warnings":[],
            "response":{"status":"ok","server_status":after,"affected_rows":0,"last_insert_id":0,
                "columns":[],"rows":[],"rows_truncated":false}})
    }

    fn read(&self, sequence: u64, before: u16, after: u16) -> Value {
        let mut value = self.statement(
            sequence,
            "SELECT value FROM items WHERE id=7",
            before,
            after,
        );
        value["response"]["status"] = json!("resultset");
        value["response"]["columns"] =
            json!([{"name":"value","family":"string","sql_type":"VARCHAR"}]);
        value["response"]["rows"] = json!([[{"kind":"string","value":"private-row-value"}]]);
        value
    }

    fn ordinary(&self) {
        self.write(
            "global-dependencies.jsonl",
            &[
                self.statement(10, "BEGIN", 2, 3),
                self.statement(11, "UPDATE items SET value=8 WHERE id=7", 3, 3),
            ],
        );
        self.write("case-a/dependencies.jsonl", &[self.read(12, 3, 3)]);
        self.write(
            "case-b/dependencies.jsonl",
            &[self.statement(13, "COMMIT", 3, 2)],
        );
    }
}

#[test]
fn cross_case_global_transaction_preserves_all_wires_and_original_locators() {
    let fixture = Fixture::new();
    fixture.ordinary();
    let prepared = prepare(&fixture.root.join("case-a")).unwrap();
    assert!(!prepared.cache_reused);
    assert_eq!(prepared.promoted.len(), 2);
    assert_eq!(prepared.wires.len(), 4);
    for sequence in 10..=13 {
        assert!(prepared.wires.contains(&(fixture.connection, sequence)));
    }
    let first = &prepared.promoted[0];
    assert_eq!(first.provenance.original_case_id, "case-a");
    assert_eq!(first.provenance.line, 1);
    assert_eq!(first.provenance.start_connection_id, fixture.connection);
    assert_eq!(first.provenance.start_query_sequence, 10);
    assert_eq!(
        first.provenance.dependencies_path,
        fixture.root.join("case-a/dependencies.jsonl")
    );
    assert_eq!(first.provenance.record_sha256.len(), 64);
    assert!(first.record.response.rows.is_empty());
    assert!(!first.record.response.no_rows());
    assert_eq!(first.record.response.materialize().unwrap().rows.len(), 1);
    assert_eq!(prepared.promoted[1].provenance.original_case_id, "case-b");
}

#[test]
fn warm_proof_reads_only_promoted_records_and_never_unrelated_case_payloads() {
    let fixture = Fixture::new();
    fixture.ordinary();
    fixture.write(
        "unrelated/dependencies.jsonl",
        &[json!({"event_type":"other","payload":"unrelated-payload".repeat(64 * 1024)})],
    );
    let cold = prepare(&fixture.root).unwrap();
    let warm = prepare(&fixture.root).unwrap();
    let promoted_bytes = fs::metadata(fixture.root.join("case-a/dependencies.jsonl"))
        .unwrap()
        .len()
        + fs::metadata(fixture.root.join("case-b/dependencies.jsonl"))
            .unwrap()
            .len();
    let global_bytes = fs::metadata(fixture.root.join("global-dependencies.jsonl"))
        .unwrap()
        .len();
    assert_eq!(warm.source_bytes, promoted_bytes);
    assert_eq!(cold.source_bytes, promoted_bytes + global_bytes);
    assert!(warm.cache_reused);
    let proof = fs::read_to_string(
        store::cache_directory(&fixture.root).join("mysql-global-transaction-proof-v2.json"),
    )
    .unwrap();
    assert!(!proof.contains("private-row-value"));
    assert!(!proof.contains("UPDATE items"));
    assert!(!proof.contains("unrelated-payload"));
}

#[test]
fn warm_proof_does_not_load_or_rebuild_the_full_transaction_facts() {
    let fixture = Fixture::new();
    fixture.ordinary();
    assert_eq!(prepare(&fixture.root).unwrap().promoted.len(), 2);
    mysql_transactions::seal(&fixture.root).unwrap();
    let facts_cache = store::cache_directory(&fixture.root).join("mysql-transactions-v1.json");
    let fragment = fixture.root.join(mysql_transactions::FRAGMENT);
    fs::remove_file(&facts_cache).unwrap();
    fs::remove_file(&fragment).unwrap();
    let warm = prepare(&fixture.root.join("case-a")).unwrap();
    assert!(warm.cache_reused);
    assert_eq!(warm.promoted.len(), 2);
    assert!(!facts_cache.exists());
    assert!(!fragment.exists());
}

#[test]
fn changed_source_and_negative_proof_cache_are_revalidated() {
    let fixture = Fixture::new();
    fixture.ordinary();
    let mut bad = fixture.read(12, 3, 3);
    bad["parse_warnings"] = json!(["incomplete result"]);
    fixture.write("case-a/dependencies.jsonl", &[bad]);
    let cold = prepare(&fixture.root).unwrap();
    assert!(cold.promoted.is_empty());
    let warm = prepare(&fixture.root).unwrap();
    assert!(warm.cache_reused);
    assert_eq!(warm.source_bytes, 0);
    fixture.write("case-a/dependencies.jsonl", &[fixture.read(12, 3, 3)]);
    let repaired = prepare(&fixture.root).unwrap();
    assert!(!repaired.cache_reused);
    assert_eq!(repaired.promoted.len(), 2);
    fixture.write(
        "unrelated/dependencies.jsonl",
        &[json!({"event_type":"other","value":1})],
    );
    assert!(!prepare(&fixture.root).unwrap().cache_reused);
}

#[test]
fn incomplete_or_ambiguous_transaction_evidence_does_not_promote() {
    for variant in [
        "missing-prefix",
        "gap",
        "duplicate",
        "open",
        "identity",
        "status",
    ] {
        let fixture = Fixture::new();
        fixture.ordinary();
        match variant {
            "missing-prefix" => fixture.write(
                "global-dependencies.jsonl",
                &[fixture.statement(11, "UPDATE items SET value=8 WHERE id=7", 3, 3)],
            ),
            "gap" => fixture.write("case-a/dependencies.jsonl", &[fixture.read(19, 3, 3)]),
            "duplicate" => fixture.write("duplicate/dependencies.jsonl", &[fixture.read(12, 3, 3)]),
            "open" => fixture.write("case-b/dependencies.jsonl", &[]),
            "identity" => {
                let mut value = fixture.read(12, 3, 3);
                value["database"] = json!("other");
                fixture.write("case-a/dependencies.jsonl", &[value]);
            }
            "status" => fixture.write("case-a/dependencies.jsonl", &[fixture.read(12, 1, 1)]),
            _ => unreachable!(),
        }
        let prepared = prepare(&fixture.root).unwrap();
        assert!(prepared.promoted.is_empty(), "{variant}");
        assert!(prepared.wires.is_empty(), "{variant}");
    }
}

#[test]
fn boundary_restarts_chain_implicit_commits_and_unknown_controls_stay_strict() {
    for sql in [
        "BEGIN",
        "START TRANSACTION",
        "COMMIT AND CHAIN",
        "ROLLBACK AND CHAIN",
        "CREATE TABLE other (id INT)",
        "ALTER TABLE items ADD COLUMN flag INT",
        "SET autocommit=1",
        "SAVEPOINT sp",
        "ROLLBACK TO SAVEPOINT sp",
        "CALL worker()",
        "XA START 'x'",
        "SELECT 1; UPDATE items SET value=8",
        "SELECT 1 /*!; COMMIT */",
    ] {
        let fixture = Fixture::new();
        fixture.ordinary();
        fixture.write(
            "case-a/dependencies.jsonl",
            &[fixture.statement(12, sql, 3, 3)],
        );
        assert!(prepare(&fixture.root).unwrap().promoted.is_empty(), "{sql}");
    }
}

#[test]
fn response_errors_truncation_and_delivery_terminations_never_prove_global_owner() {
    for variant in [
        "error",
        "outcome",
        "truncated",
        "shape",
        "warning",
        "multi",
        "missing-status",
    ] {
        let fixture = Fixture::new();
        fixture.ordinary();
        let mut value = fixture.read(12, 3, 3);
        match variant {
            "error" => value["response"]["error_code"] = json!(1234),
            "outcome" => value["outcome"] = json!("client_terminated"),
            "truncated" => value["response"]["rows_truncated"] = json!(true),
            "shape" => value["response"]["rows"] = json!([[]]),
            "warning" => value["parse_warnings"] = json!(["warning"]),
            "multi" => value["response"]["server_status"] = json!(11),
            "missing-status" => value["response"]["server_status"] = Value::Null,
            _ => unreachable!(),
        }
        fixture.write("case-a/dependencies.jsonl", &[value]);
        assert!(
            prepare(&fixture.root).unwrap().promoted.is_empty(),
            "{variant}"
        );
    }
}

#[test]
fn connection_reuse_never_promotes_later_case_owned_write_transaction() {
    let fixture = Fixture::new();
    fixture.ordinary();
    fixture.write(
        "case-b/dependencies.jsonl",
        &[
            fixture.statement(13, "COMMIT", 3, 2),
            fixture.statement(14, "BEGIN", 2, 3),
            fixture.statement(15, "DELETE FROM items WHERE id=7", 3, 3),
            fixture.statement(16, "COMMIT", 3, 2),
        ],
    );
    let prepared = prepare(&fixture.root).unwrap();
    assert_eq!(prepared.promoted.len(), 2);
    assert_eq!(prepared.wires.len(), 4);
    assert!(!prepared.wires.contains(&(fixture.connection, 14)));
    assert!(!prepared.wires.contains(&(fixture.connection, 16)));
}

#[test]
fn implicit_start_and_prepared_dml_preserve_global_owner() {
    let fixture = Fixture::new();
    fixture.write("global-dependencies.jsonl", &[fixture.read(1, 0, 1)]);
    let mut insert = fixture.statement(2, "INSERT INTO items (id) VALUES (?)", 1, 1);
    insert["command"] = json!("COM_STMT_EXECUTE");
    insert["params"] = json!([{"kind":"signed","value":7}]);
    insert["response"]["affected_rows"] = json!(1);
    insert["response"]["last_insert_id"] = json!(7);
    fixture.write(
        "unselected/dependencies.jsonl",
        &[insert, fixture.statement(3, "ROLLBACK", 1, 0)],
    );
    let prepared = prepare(&fixture.root).unwrap();
    assert_eq!(prepared.promoted.len(), 2);
    assert_eq!(prepared.wires.len(), 3);
    assert_eq!(
        prepared.promoted[0].provenance.original_case_id,
        "unselected"
    );
}

#[test]
fn missing_recording_boundary_returns_empty_without_creating_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let prepared = prepare(temporary.path()).unwrap();
    assert!(prepared.promoted.is_empty());
    assert!(prepared.wires.is_empty());
    assert_eq!(prepared.source_bytes, 0);
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
}
