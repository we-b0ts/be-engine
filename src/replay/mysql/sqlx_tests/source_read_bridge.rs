//! Global Source proof supplements Case metadata without consuming Global SQL.
use super::*;

fn records() -> (Vec<Value>, Vec<Value>) {
    let base = traffic_protocol_mysql::transaction_delivery::test_support::records();
    let mut case = base[1..4].to_vec();
    for (record, sequence) in case.iter_mut().zip([1, 3, 4]) {
        record["query_sequence"] = json!(sequence);
    }
    let mut global = case[0].clone();
    global["query_sequence"] = json!(2);
    global["server_status_before"] = json!(1);
    global["sql"] = json!("SELECT id FROM teams WHERE id=2");
    global["response"]["rows"] = json!([[{"kind":"integer","value":2}]]);
    (case, vec![global])
}

async fn read(client: &mut MySqlConnection, table: &str, id: i32) {
    assert_eq!(
        sqlx::query(&format!("SELECT id FROM {table} WHERE id=?"))
            .bind(id)
            .fetch_one(client)
            .await
            .unwrap()
            .get::<i32, _>(0),
        id
    );
}

async fn write(client: &mut MySqlConnection) {
    sqlx::query("UPDATE users SET active=? WHERE id=?")
        .bind(1_i32)
        .bind(1_i32)
        .execute(client)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_global_prewrite_read_proves_single_write_commit_without_consuming_the_read() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (case, global) = records();
        let (temp, addr, runtime, task) = fixture_with_global(&case, &global, None).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut client = connect(addr, &ca).await;
        read(&mut client, "users", 1).await;
        write(&mut client).await;
        {
            let state = runtime.state.lock().await;
            assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
            assert_eq!(state.unused_exchanges(ReplaySource::Startup).len(), 1);
            let end = state
                .mysql
                .exchanges
                .iter()
                .position(|exchange| exchange.record.sql.as_deref() == Some("COMMIT"))
                .unwrap();
            let diagnostic = state.mysql.transaction_equivalence.diagnostic(end).unwrap();
            assert_eq!(diagnostic["source_transactions"][0]["write_count"], 1);
            assert_eq!(
                diagnostic["source_transactions"][0]["target_status_before"],
                2
            );
            assert_eq!(
                diagnostic["source_transactions"][0]["target_status_after"],
                2
            );
        }
        read(&mut client, "teams", 2).await;
        let state = runtime.state.lock().await;
        assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
        assert!(state.unused_exchanges(ReplaySource::Startup).is_empty());
        assert!(
            state.snapshot_report().is_dirty(),
            "an implicit low-level run cannot certify the Startup phase"
        );
        assert_eq!(state.startup_phase.report().status, "phase_unverified");
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_global_read_after_a_write_does_not_authorize_a_commit_omission() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut case, global) = records();
        case[0] = case[1].clone();
        case[0]["query_sequence"] = json!(1);
        case[0]["server_status_before"] = json!(0);
        case.remove(1);
        case[1]["query_sequence"] = json!(3);
        let (temp, addr, runtime, task) = fixture_with_global(&case, &global, None).await;
        let ca = temp
            .path()
            .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem");
        let mut client = connect(addr, &ca).await;
        write(&mut client).await;
        read(&mut client, "teams", 2).await;
        let state = runtime.state.lock().await;
        let unused = state.unused_exchanges(ReplaySource::Case);
        assert_eq!(unused.len(), 1);
        let proof = unused[0].diagnostic.as_ref().unwrap();
        assert_eq!(proof["reason"], "source_sequence_gap");
        assert_eq!(proof["source_proof_status"], "incomplete");
        assert_eq!(
            proof["source_proof_rejection"]["missing_query_sequences"],
            json!([2])
        );
        assert!(state.unused_exchanges(ReplaySource::Startup).is_empty());
        assert!(state.snapshot_report().is_dirty());
        task.abort();
    })
    .await
    .unwrap();
}
