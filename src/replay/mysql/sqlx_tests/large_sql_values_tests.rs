//! Large recorded JSON literals with ordinary SQLx text/prepared clients over TLS.
use super::*;
use sqlx::Executor;

const SQL: &str =
    "UPDATE entries_0031 SET json=?, is_active=?, updated_at=? WHERE entries_0031.id=?";

#[tokio::test]
async fn target_observation_io_failure_preserves_global_matching_and_rejects_case_candidates() {
    let sql = "SELECT id FROM entries";
    for global in [false, true] {
        let record = exchange(sql, json!({"status":"ok", "affected_rows":0}));
        let (temp, _addr, runtime, task) = fixture_with_global(
            if global {
                &[]
            } else {
                std::slice::from_ref(&record)
            },
            if global {
                std::slice::from_ref(&record)
            } else {
                &[]
            },
            Some("format: traffic-policy/v2\nrules: []\n"),
        )
        .await;
        let store =
            crate::policy_evidence::WitnessStore::new(&temp.path().join("io-failure")).unwrap();
        store.fail_writes_for_test().unwrap();
        let mut state = runtime.state.lock().await;
        state
            .replay_policy
            .as_mut()
            .unwrap()
            .request_contracts
            .configure_witnesses(store, false)
            .unwrap();
        let identity = ReplaySessionIdentity {
            target: Some(TargetKey {
                host: "127.0.0.1".into(),
                port: 3306,
            }),
            database: Some("appdb".into()),
            username: Some("root".into()),
        };
        let matched = state.match_exchange(&identity, "COM_QUERY", Some(sql), None);
        assert_eq!(matched.is_some(), global);
        assert!(
            state
                .mysql
                .events
                .metadata_warnings
                .iter()
                .any(|warning| warning.contains("SQL Target observation unavailable"))
        );
        let manifest = state
            .replay_policy
            .as_ref()
            .unwrap()
            .request_contracts
            .witness_manifest()
            .unwrap();
        assert!(!manifest.complete);
        assert!(manifest.omitted > 0);
        assert!(manifest.graph().unwrap().targets.is_empty());
        assert_eq!(
            state.mysql.exchanges[0].status,
            if global {
                ReplayExchangeStatus::Responding
            } else {
                ReplayExchangeStatus::Available
            }
        );
        task.abort();
    }
}

fn text_sql(payload: &str, timestamp: &str, id: i64) -> String {
    format!(
        "UPDATE entries_0031 SET json='{payload}', is_active=0, updated_at='{timestamp}' WHERE entries_0031.id={id}"
    )
}

#[tokio::test]
async fn large_sql_value_literals_replay_json_times_and_preserve_stable_values_and_consumption() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let policy = r#"
version: 3
expected_response: assertions_only
dependency_rules:
- id: large-json-time
  protocol: mysql
  mysql:
    database: appdb
    sql: UPDATE {{table}} SET json=?, is_active=?, updated_at=? WHERE {{table}}.id=?
    table_series: {prefix: entries_, start: 0, end: 1023, width: 4}
    sql_values:
      0:
        json:
          /status/updatedAt: {time: replay_now, tolerance: 5s, format: "%+"}
      2: {time: replay_now, tolerance: 5s}
"#;
        let recorded_payload = json!({
            "name":"stable", "data":"x".repeat(300_000),
            "status":{"updatedAt":"2020-01-01T00:00:00+00:00"}
        })
        .to_string();
        let recorded_sql = text_sql(&recorded_payload, "2020-01-01 00:00:00", 7);
        assert!(recorded_sql.len() > 256 * 1024 && recorded_sql.len() < 1024 * 1024);
        for source_prepared in [false, true] {
            for target_prepared in [false, true] {
                let mut write = exchange(&recorded_sql, json!({"status":"ok","affected_rows":1}));
                if source_prepared {
                    write["command"] = json!("COM_STMT_EXECUTE");
                    write["sql"] = json!(SQL);
                    write["params"] = json!([
                        {"kind":"string","value":recorded_payload},
                        {"kind":"integer","value":0},
                        {"kind":"datetime","value":"2020-01-01 00:00:00"},
                        {"kind":"integer","value":7}
                    ]);
                }
                let (temp, addr, runtime, task) = fixture_with_policy(&[write], Some(policy)).await;
                let path = temp
                    .path()
                    .join(".traffic-e2e/local/recordings/case-id/dependencies.jsonl");
                let original = std::fs::read(&path).unwrap();
                let mut client = connect(
                    addr,
                    &temp
                        .path()
                        .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
                )
                .await;
                // Wrong stable JSON, key, and stale time cannot consume evidence.
                // A correct call succeeds once in each text/prepared combination.
                for attempt in 0..5 {
                    let now = chrono::Utc::now();
                    let timestamp = now.naive_utc().format("%Y-%m-%d %H:%M:%S%.6f").to_string();
                    let observed = if attempt == 2 {
                        "2020-01-01T00:00:00+00:00".to_string()
                    } else {
                        now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                    };
                    let payload = json!({
                        "name":if attempt == 0 {"changed"} else {"stable"},
                        "data":"x".repeat(300_000), "status":{"updatedAt":observed}
                    })
                    .to_string();
                    let id = if attempt == 1 { 8_i64 } else { 7 };
                    let result = if target_prepared {
                        sqlx::query(SQL)
                            .bind(&payload)
                            .bind(0_i64)
                            .bind(now.naive_utc())
                            .bind(id)
                            .execute(&mut client)
                            .await
                    } else {
                        (&mut client)
                            .execute(text_sql(&payload, &timestamp, id).as_str())
                            .await
                    };
                    if attempt == 3 {
                        assert_eq!(result.unwrap().rows_affected(), 1);
                    } else {
                        assert!(
                            result.is_err(),
                            "stable values, time and finite consumption remain strict"
                        );
                    }
                }
                client.close().await.unwrap();
                let state = runtime.state.lock().await;
                assert_eq!(state.mysql.events.matched_query_count, 1);
                assert_eq!(state.mysql.events.unmatched_queries.len(), 4);
                assert!(state.unused_exchanges(ReplaySource::Case).is_empty());
                let report = state.replay_policy.as_ref().unwrap().report();
                assert_eq!(report.dependency_rules[0].time_validations, 2);
                assert_eq!(report.dependency_rules[0].matches, 1);
                assert_eq!(std::fs::read(path).unwrap(), original);
                task.abort();
            }
        }
    })
    .await
    .expect("large SQL value replay timed out");
}

#[tokio::test]
async fn payload_evidence_budget_does_not_reject_a_valid_large_native_sql_match() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let sql = format!(
            "UPDATE entries SET payload='{}' WHERE id=7",
            "x".repeat(1024 * 1024 + 32)
        );
        let write = exchange(&sql, json!({"status":"ok","affected_rows":1}));
        let (temp, addr, runtime, task) =
            fixture_with_policy(&[write], Some("format: traffic-policy/v2\nrules: []\n")).await;
        let mut client = connect(
            addr,
            &temp
                .path()
                .join(".traffic-e2e/local/recordings/case-id/.replay/ca.pem"),
        )
        .await;
        assert_eq!(
            (&mut client)
                .execute(sql.as_str())
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        client.close().await.unwrap();
        let state = runtime.state.lock().await;
        assert_eq!(state.mysql.events.matched_query_count, 1);
        let owner = &state.replay_policy.as_ref().unwrap().request_contracts;
        owner.seal_witnesses().unwrap();
        let manifest = owner.witness_manifest().unwrap();
        assert!(manifest.complete && manifest.omitted == 0);
        let case = temp.path().join(".traffic-e2e/local/recordings/case-id");
        let report = case.join(".replay/replay.json");
        std::fs::write(
            &report,
            serde_json::to_vec(&state.snapshot_report()).unwrap(),
        )
        .unwrap();
        let private = crate::policy_evidence::verify(&report, &manifest).unwrap();
        let retained = manifest
            .witnesses()
            .unwrap()
            .into_iter()
            .filter(|w| w.target_sha256.is_some())
            .any(|witness| {
                let (_, target) = crate::policy_evidence::read(&private, &witness, &case).unwrap();
                let target: Value = serde_json::from_slice(&target.unwrap()).unwrap();
                target["sql"].as_str() == Some(sql.as_str())
            });
        assert!(retained, "large genuine SQL request must remain readable");
        task.abort();
    })
    .await
    .expect("large native SQL budget regression timed out");
}
