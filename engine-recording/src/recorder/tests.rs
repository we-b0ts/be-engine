use crate::RecordingConfig;
use crate::protocols::recording::events::{
    MysqlColumn, MysqlExchangeEvent, MysqlExchangeResponse, MysqlQueryEvent, MysqlValue,
    RecorderEvent,
};
use chrono::Utc;
use std::time::Duration;

use super::*;
use crate::active_case::ActiveCaseRegistry;

async fn flush_case_dependencies(recorder: &Recorder, case: &CaseContext) {
    let _guard = recorder.dependency_write_lock.lock().await;
    recorder
        .flush_case_dependency_files(&recorder.case_staging_dir(case))
        .await
        .unwrap();
}

async fn flush_global_dependencies(recorder: &Recorder) {
    let _guard = recorder.dependency_write_lock.lock().await;
    recorder.flush_global_dependency_files().await.unwrap();
}

fn test_proxy_error(message: &str) -> RecorderEvent {
    RecorderEvent::ProxyError(ProxyErrorEvent {
        id: Uuid::new_v4(),
        connection_id: None,
        timestamp: Utc::now(),
        protocol: "test".to_string(),
        client_addr: None,
        target: Some("upstream".to_string()),
        error: message.to_string(),
    })
}

fn test_mysql_query() -> RecorderEvent {
    RecorderEvent::MysqlQuery(MysqlQueryEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: None,
        command: "COM_QUERY".to_string(),
        query: Some("select 1".to_string()),
        payload_len: 8,
    })
}

#[tokio::test]
async fn traffic_jsonl_off_skips_the_file() {
    let temp = tempfile::tempdir().unwrap();
    let config = RecordingConfig {
        output_dir: temp.path().to_path_buf(),
        traffic_jsonl: TrafficJsonlMode::Off,
        ..Default::default()
    };
    let recorder = Recorder::new_with_recording_config(&config).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };
    let event = test_proxy_error("boom");

    recorder.record(event.clone()).await.unwrap();
    recorder
        .append_case_dependency(&case, &event, "active_window")
        .await
        .unwrap();
    recorder.publish_case(&case).await.unwrap();
    recorder.finish_run().await.unwrap();

    assert!(!recorder.run_dir.join("traffic.jsonl").exists());
    let dependencies = crate::recorder::test_io::read_to_string(
        recorder.case_dir(&case).join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    assert!(dependencies.contains("\"event_type\":\"proxy_error\""));
}

#[tokio::test]
async fn traffic_jsonl_errors_keeps_only_diagnostic_events() {
    let temp = tempfile::tempdir().unwrap();
    let config = RecordingConfig {
        output_dir: temp.path().to_path_buf(),
        traffic_jsonl: TrafficJsonlMode::Errors,
        ..Default::default()
    };
    let recorder = Recorder::new_with_recording_config(&config).await.unwrap();

    recorder.record(test_mysql_query()).await.unwrap();
    recorder.record(test_proxy_error("boom")).await.unwrap();
    recorder.finish_run().await.unwrap();

    let raw = crate::recorder::test_io::read_to_string(recorder.run_dir.join("traffic.jsonl"))
        .await
        .unwrap();
    assert_eq!(raw.lines().count(), 1);
    assert!(raw.contains("\"event_type\":\"proxy_error\""));
}

#[tokio::test]
async fn traffic_jsonl_full_flushes_buffer_when_run_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let path = recorder.run_dir.join("traffic.jsonl");

    recorder.record(test_proxy_error("boom")).await.unwrap();
    assert!(tokio::fs::read(&path).await.unwrap().is_empty());

    recorder.finish_run().await.unwrap();
    assert!(!tokio::fs::read(&path).await.unwrap().is_empty());
}

#[tokio::test]
async fn traffic_jsonl_flushes_on_the_configured_interval() {
    let temp = tempfile::tempdir().unwrap();
    let config = RecordingConfig {
        output_dir: temp.path().to_path_buf(),
        jsonl_flush_interval_ms: 10,
        ..Default::default()
    };
    let recorder = Recorder::new_with_recording_config(&config).await.unwrap();
    let path = recorder.run_dir.join("traffic.jsonl");

    recorder.record(test_proxy_error("boom")).await.unwrap();
    assert!(tokio::fs::read(&path).await.unwrap().is_empty());

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !tokio::fs::read(&path).await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queued_dependencies_hold_bootstrap_reservations_until_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let config = RecordingConfig {
        output_dir: temp.path().to_path_buf(),
        traffic_jsonl: TrafficJsonlMode::Off,
        writer_queue_capacity: 4_096,
        ..Default::default()
    };
    let recorder = Recorder::new_with_recording_config(&config).await.unwrap();
    let active_cases = ActiveCaseRegistry::default();

    for sequence in 0..2_048 {
        let event = test_proxy_error(&format!("{sequence}:{}", "x".repeat(4_096)));
        let targets = active_cases.current_targets_for_event();
        recorder
            .try_record_event(event, targets, None, false)
            .unwrap();
    }

    active_cases.close_bootstrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        active_cases.wait_for_bootstrap_dependencies(),
    )
    .await
    .expect("queued dependency reservations should drain");
    recorder.flush_global_dependency_files().await.unwrap();

    let dependencies = crate::recorder::test_io::read_to_string(
        recorder.run_dir.join("global-dependencies.jsonl"),
    )
    .await
    .unwrap();
    assert_eq!(dependencies.lines().count(), 2_048);
}

#[tokio::test]
async fn full_writer_queue_fails_recording_without_waiting_for_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let config = RecordingConfig {
        output_dir: temp.path().to_path_buf(),
        writer_queue_capacity: 1,
        ..Default::default()
    };
    let recorder = Recorder::new_with_recording_config(&config).await.unwrap();

    recorder.record(test_proxy_error("first")).await.unwrap();
    let error = recorder
        .record(test_proxy_error("second"))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("recording writer queue is full"));
    assert!(recorder.flush_traffic().await.is_err());
}

#[tokio::test]
async fn explicit_run_id_uses_exact_directory_and_rejects_duplicates() {
    let temp = tempfile::tempdir().unwrap();
    let run_id = "20260721153045";
    let config = RecordingConfig {
        output_dir: temp.path().to_path_buf(),
        ..RecordingConfig::default()
    };
    let recorder =
        Recorder::new_with_recording_config_and_run_id(&config, Some(run_id.to_string()))
            .await
            .unwrap();
    assert_eq!(recorder.run_dir.as_ref(), &temp.path().join(run_id));
    drop(recorder);

    let error =
        match Recorder::new_with_recording_config_and_run_id(&config, Some(run_id.to_string()))
            .await
        {
            Ok(_) => panic!("duplicate explicit run ID must fail"),
            Err(error) => error,
        };
    assert!(format!("{error:#}").contains("failed to create recording run dir"));
}

#[tokio::test]
async fn case_dependency_records_match_reason() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };
    let event = RecorderEvent::ProxyError(ProxyErrorEvent {
        id: Uuid::new_v4(),
        connection_id: None,
        timestamp: Utc::now(),
        protocol: "test".to_string(),
        client_addr: None,
        target: Some("upstream".to_string()),
        error: "boom".to_string(),
    });

    recorder
        .append_case_dependency(&case, &event, "active_window")
        .await
        .unwrap();
    flush_case_dependencies(&recorder, &case).await;

    let raw = crate::recorder::test_io::read_to_string(
        recorder.case_staging_dir(&case).join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(value["event_type"], "proxy_error");
    assert_eq!(value["capture"]["attribution"]["kind"], "case");
    assert_eq!(
        value["capture"]["attribution"]["origin_case_id"],
        case.id.to_string()
    );
}

#[tokio::test]
async fn case_files_include_uri_group_when_present() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "record api".to_string(),
        uri_group: Some("api-users".to_string()),
    };

    recorder
        .write_case_json(&case, "request.json", &serde_json::json!({ "ok": true }))
        .await
        .unwrap();

    assert!(
        recorder
            .case_staging_dir(&case)
            .join("request.json")
            .exists()
    );
}

#[tokio::test]
async fn global_dependency_summary_is_generated_only_when_run_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let event = RecorderEvent::ProxyError(ProxyErrorEvent {
        id: Uuid::new_v4(),
        connection_id: None,
        timestamp: Utc::now(),
        protocol: "test".to_string(),
        client_addr: None,
        target: Some("upstream".to_string()),
        error: "boom".to_string(),
    });

    recorder
        .append_global_dependency(&event, "bootstrap_window", "bootstrap", "bootstrap_window")
        .await
        .unwrap();
    flush_global_dependencies(&recorder).await;

    let raw = crate::recorder::test_io::read_to_string(
        recorder.run_dir.join("global-dependencies.jsonl"),
    )
    .await
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(value["event_type"], "proxy_error");
    assert_eq!(value["capture"]["attribution"]["kind"], "startup");
    assert_eq!(value["capture"]["phase"], "startup");
    assert!(
        !tokio::fs::try_exists(recorder.run_dir.join("global-dependencies-summary.json"))
            .await
            .unwrap()
    );

    assert!(!recorder.finish_run().await.unwrap());
    assert!(
        !recorder
            .run_dir
            .join("indexes/startup-dependencies")
            .exists()
    );
    let global = recorder.run_dir.join("global-dependencies.jsonl");
    let (global_index, _) =
        crate::dependency_index::global::load_global_index(&global, |_| Ok(())).unwrap();
    assert_eq!(global_index.records.count, 1);
    let summary_raw = crate::recorder::test_io::read_to_string(
        recorder.run_dir.join("global-dependencies-summary.json"),
    )
    .await
    .unwrap();
    let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
    assert_eq!(summary["total_events"], 1);
    assert_eq!(summary["event_types"]["proxy_error"], 1);
    let pre_readiness_raw = crate::recorder::test_io::read_to_string(
        recorder.run_dir.join("pre-readiness-traffic-summary.json"),
    )
    .await
    .unwrap();
    let pre_readiness: serde_json::Value = serde_json::from_str(&pre_readiness_raw).unwrap();
    assert_eq!(pre_readiness["phase"], "bootstrap");
    assert_eq!(pre_readiness["bootstrap_events"], 1);
    assert_eq!(pre_readiness["excluded_events"], 1);
    assert_eq!(pre_readiness["data_interactions"], 0);
}

#[tokio::test]
async fn case_dependency_summary_skips_successful_prepare() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };

    recorder
        .append_case_dependency(
            &case,
            &RecorderEvent::MysqlExchange(mysql_exchange(
                "COM_STMT_PREPARE",
                Some("SELECT `id`, `name` FROM `user` WHERE `id` = ?"),
                "stmt_prepare",
                vec![mysql_column("id", "user", "id", "integer", "INT")],
                Vec::new(),
                None,
                None,
            )),
            "active_window",
        )
        .await
        .unwrap();

    let case_dir = recorder.case_staging_dir(&case);
    assert!(!case_dir.join("dependencies.jsonl").exists());
    assert!(!case_dir.join("dependencies-summary.json").exists());

    recorder
        .append_case_dependency(
            &case,
            &RecorderEvent::MysqlExchange(mysql_exchange(
                "COM_STMT_EXECUTE",
                Some("SELECT `id`, `name` FROM `user` WHERE `id` = ?"),
                "resultset",
                vec![
                    mysql_column("id", "user", "id", "integer", "INT"),
                    mysql_column("name", "user", "name", "string", "VARCHAR"),
                ],
                vec![vec![
                    MysqlValue {
                        kind: "integer".to_string(),
                        value: Some(serde_json::json!(1)),
                        raw: None,
                    },
                    MysqlValue {
                        kind: "string".to_string(),
                        value: Some(serde_json::json!("alice")),
                        raw: None,
                    },
                ]],
                None,
                None,
            )),
            "active_window",
        )
        .await
        .unwrap();

    recorder
        .append_case_dependency(
            &case,
            &RecorderEvent::MysqlExchange(mysql_exchange(
                "COM_STMT_PREPARE",
                Some("INSERT INTO request_log_202607 (uuid) VALUES (?)"),
                "error",
                Vec::new(),
                Vec::new(),
                Some(1146),
                Some("Table 'pluto_log.request_log_202607' doesn't exist"),
            )),
            "active_window",
        )
        .await
        .unwrap();

    flush_case_dependencies(&recorder, &case).await;

    let raw = crate::recorder::test_io::read_to_string(case_dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    assert_eq!(raw.lines().count(), 3);
    let prepare = raw
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|value| value["response"]["status"] == "stmt_prepare")
        .unwrap();
    assert_eq!(prepare["capture"]["semantic_required"], false);

    summary::write_case_dependency_summary(&case_dir, recorder.evidence.clone())
        .await
        .unwrap();
    let summary_raw =
        crate::recorder::test_io::read_to_string(case_dir.join("dependencies-summary.json"))
            .await
            .unwrap();
    let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
    assert_eq!(summary["total_events"], 2);
    assert_eq!(summary["event_types"]["mysql_exchange"], 2);
    assert_eq!(summary["mysql"]["semantic_exchanges"], 2);
    assert_eq!(summary["mysql"]["executed"]["total"], 1);
    assert_eq!(summary["mysql"]["executed"]["crud"]["select"], 1);
    assert_eq!(summary["mysql"]["failed"]["total"], 1);
    assert_eq!(summary["mysql"]["failed"]["by_phase"]["prepare"], 1);
    assert_eq!(summary["mysql"]["failed"]["crud"]["insert"], 1);
    assert_eq!(summary["mysql"]["tables"]["user"]["executed"]["select"], 1);
    assert_eq!(
        summary["mysql"]["tables"]["request_log_202607"]["failed"]["insert"],
        1
    );
}

#[tokio::test]
async fn case_dependency_skips_successful_mysql_session_setup() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };

    for (sql, status) in [
        ("SET NAMES utf8", "ok"),
        (
            "SET sql_mode='NO_AUTO_CREATE_USER,STRICT_TRANS_TABLES'",
            "ok",
        ),
        ("SELECT 2", "resultset"),
        ("SHOW COLLATION", "resultset"),
        ("SHOW WARNINGS", "resultset"),
        ("SELECT @@session.tx_isolation", "resultset"),
        (
            "/* mysql-connector-java-5.1.10 ( Revision: ${svn.Revision} ) */\
             SELECT @@session.auto_increment_increment",
            "resultset",
        ),
        (
            "/* mysql-connector-java-5.1.10 ( Revision: ${svn.Revision} ) */\
             SHOW VARIABLES WHERE Variable_name = 'character_set_client' \
             OR Variable_name = 'transaction_isolation' \
             OR Variable_name = 'max_allowed_packet'",
            "resultset",
        ),
    ] {
        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_QUERY",
                    Some(sql),
                    status,
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                )),
                "active_window",
            )
            .await
            .unwrap();
    }

    let case_dir = recorder.case_staging_dir(&case);
    assert!(!case_dir.join("dependencies.jsonl").exists());
    assert!(!case_dir.join("dependencies-summary.json").exists());

    recorder
        .append_case_dependency(
            &case,
            &RecorderEvent::MysqlExchange(mysql_exchange(
                "COM_QUERY",
                Some("SET @tenant_id = 1"),
                "ok",
                Vec::new(),
                Vec::new(),
                None,
                None,
            )),
            "active_window",
        )
        .await
        .unwrap();

    flush_case_dependencies(&recorder, &case).await;

    let raw = crate::recorder::test_io::read_to_string(case_dir.join("dependencies.jsonl"))
        .await
        .unwrap();
    assert_eq!(raw.lines().count(), 9);
    assert!(raw.contains("SET @tenant_id = 1"));
    assert_eq!(raw.lines().filter(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["capture"]["semantic_required"] == true).count(), 1);
}

#[tokio::test]
async fn autocommit_controls_remain_semantic_evidence_for_replay_classification() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };
    for (sql, status) in [
        ("SET AUTOCOMMIT=0", "ok"),
        ("SET AUTOCOMMIT=1", "ok"),
        ("SET SESSION AUTOCOMMIT=1", "ok"),
        ("SET AUTOCOMMIT=1", "error"),
        ("SET sql_mode='',autocommit=1", "ok"),
        ("SET sql_mode='',`autocommit`=1", "ok"),
        ("SET sql_mode='' /*! ,autocommit=1 */", "ok"),
    ] {
        recorder
            .append_case_dependency(
                &case,
                &RecorderEvent::MysqlExchange(mysql_exchange(
                    "COM_QUERY",
                    Some(sql),
                    status,
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                )),
                "active_window",
            )
            .await
            .unwrap();
    }
    flush_case_dependencies(&recorder, &case).await;
    let raw = crate::recorder::test_io::read_to_string(
        recorder.case_staging_dir(&case).join("dependencies.jsonl"),
    )
    .await
    .unwrap();
    let records: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 7);
    assert_eq!(records[0]["sql"], "SET AUTOCOMMIT=0");
    assert_eq!(records[1]["sql"], "SET AUTOCOMMIT=1");
    assert_eq!(records[3]["response"]["status"], "error");
}

#[tokio::test]
async fn case_dependency_routes_mysql_protocol_details_to_debug_file() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".to_string(),
        uri_group: None,
    };
    let event = RecorderEvent::MysqlQuery(MysqlQueryEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: Some("127.0.0.1:12345".to_string()),
        command: "COM_QUERY".to_string(),
        query: Some("select 1".to_string()),
        payload_len: 9,
    });

    recorder
        .append_case_dependency(&case, &event, "active_window")
        .await
        .unwrap();
    flush_case_dependencies(&recorder, &case).await;

    let case_dir = recorder.case_staging_dir(&case);
    assert!(!case_dir.join("dependencies.jsonl").exists());
    let raw = crate::recorder::test_io::read_to_string(case_dir.join("dependencies-debug.jsonl"))
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(value["event_type"], "mysql_query");
    assert_eq!(value["capture"]["attribution"]["kind"], "case");
    assert_eq!(
        value["capture"]["attribution"]["origin_case_id"],
        case.id.to_string()
    );
}

#[tokio::test]
async fn publish_case_moves_staging_to_published_and_updates_report() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "record api".to_string(),
        uri_group: Some("api-users".to_string()),
    };

    recorder
        .write_case_json(&case, "request.json", &serde_json::json!({ "ok": true }))
        .await
        .unwrap();
    recorder.publish_case(&case).await.unwrap();

    assert!(!recorder.case_staging_dir(&case).exists());
    let published_case_dir = recorder
        .run_dir
        .join("apis/api-users")
        .join(case.id.to_string());
    assert!(published_case_dir.join("request.json").exists());
    let dependencies =
        crate::recorder::test_io::read_to_string(published_case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
    assert!(dependencies.is_empty());
    let summary_raw = crate::recorder::test_io::read_to_string(
        published_case_dir.join("dependencies-summary.json"),
    )
    .await
    .unwrap();
    let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
    assert_eq!(summary["source"], "dependencies.jsonl");
    assert_eq!(summary["total_events"], 0);
    assert_eq!(summary["event_types"], serde_json::json!({}));
    let report_raw =
        crate::recorder::test_io::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
    let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
    assert_eq!(report["published_cases"], 1);
    assert_eq!(report["failed_cases"], 0);
}

#[tokio::test]
async fn finalized_case_ignores_late_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "record api".to_string(),
        uri_group: Some("api-users".to_string()),
    };
    let event = RecorderEvent::ProxyError(ProxyErrorEvent {
        id: Uuid::new_v4(),
        connection_id: None,
        timestamp: Utc::now(),
        protocol: "test".to_string(),
        client_addr: None,
        target: Some("upstream".to_string()),
        error: "late".to_string(),
    });

    recorder
        .write_case_json(&case, "request.json", &serde_json::json!({ "ok": true }))
        .await
        .unwrap();
    recorder.publish_case(&case).await.unwrap();
    recorder
        .append_case_dependency(&case, &event, "active_window")
        .await
        .unwrap();

    assert!(!recorder.case_staging_dir(&case).exists());
    let published_case_dir = recorder
        .run_dir
        .join("apis/api-users")
        .join(case.id.to_string());
    let dependencies =
        crate::recorder::test_io::read_to_string(published_case_dir.join("dependencies.jsonl"))
            .await
            .unwrap();
    assert!(dependencies.is_empty());
    let summary_raw = crate::recorder::test_io::read_to_string(
        published_case_dir.join("dependencies-summary.json"),
    )
    .await
    .unwrap();
    let summary: serde_json::Value = serde_json::from_str(&summary_raw).unwrap();
    assert_eq!(summary["total_events"], 0);
}

#[tokio::test]
async fn fail_case_moves_staging_to_failed_and_records_error() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "record api".to_string(),
        uri_group: Some("api-users".to_string()),
    };

    recorder
        .write_case_json(
            &case,
            "expected-response.json.truncated",
            &serde_json::json!({ "truncated": true }),
        )
        .await
        .unwrap();
    recorder
        .fail_case(
            &case,
            "expected_response_body_truncated",
            "response exceeded recording limit",
        )
        .await
        .unwrap();

    assert!(!recorder.case_staging_dir(&case).exists());
    let failed_dir = recorder.case_failed_dir(&case);
    assert!(failed_dir.join("expected-response.json.truncated").exists());
    assert!(failed_dir.join("recording-error.json").exists());
    assert!(
        !recorder
            .run_dir
            .join("apis/api-users")
            .join(case.id.to_string())
            .exists()
    );
    let errors_raw =
        crate::recorder::test_io::read_to_string(recorder.run_dir.join("errors.jsonl"))
            .await
            .unwrap();
    assert!(errors_raw.contains("expected_response_body_truncated"));
    let report_raw =
        crate::recorder::test_io::read_to_string(recorder.run_dir.join("recording-run.json"))
            .await
            .unwrap();
    let report: serde_json::Value = serde_json::from_str(&report_raw).unwrap();
    assert_eq!(report["status"], "running");
    assert_eq!(report["published_cases"], 0);
    assert_eq!(report["failed_cases"], 1);
}

#[tokio::test]
async fn startup_global_dependency_routes_mysql_protocol_details_to_debug_file() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
    let event = RecorderEvent::MysqlQuery(MysqlQueryEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        client_addr: Some("127.0.0.1:12345".to_string()),
        command: "COM_QUERY".to_string(),
        query: Some("select 1".to_string()),
        payload_len: 9,
    });

    recorder
        .append_global_dependency(&event, "bootstrap_window", "bootstrap", "bootstrap_window")
        .await
        .unwrap();
    flush_global_dependencies(&recorder).await;

    assert!(!recorder.run_dir.join("global-dependencies.jsonl").exists());
    let raw = crate::recorder::test_io::read_to_string(
        recorder.run_dir.join("global-dependencies-debug.jsonl"),
    )
    .await
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
    assert_eq!(value["event_type"], "mysql_query");
    assert_eq!(value["capture"]["attribution"]["kind"], "startup");
    assert_eq!(value["capture"]["phase"], "startup");
}

fn mysql_exchange(
    command: &str,
    sql: Option<&str>,
    status: &str,
    columns: Vec<MysqlColumn>,
    rows: Vec<Vec<MysqlValue>>,
    error_code: Option<u16>,
    error_message: Option<&str>,
) -> MysqlExchangeEvent {
    MysqlExchangeEvent {
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        query_sequence: 1,
        request_started_at: Utc::now(),
        timestamp: Utc::now(),
        client_addr: None,
        route_name: None,
        target_host: Some("mysql.internal".to_string()),
        target_port: Some(3306),
        target_addr: Some("mysql.internal:3306".to_string()),
        upstream_addr: Some("10.0.0.1:3306".to_string()),
        username: Some("root".to_string()),
        database: Some("appdb".to_string()),
        command: command.to_string(),
        sql: sql.map(ToOwned::to_owned),
        statement_id: Some(1),
        params: None,
        server_status_before: None,
        response: MysqlExchangeResponse {
            wire_prefix: Vec::new(),
            server_status: None,
            status: status.to_string(),
            error_code,
            error_message: error_message.map(ToOwned::to_owned),
            affected_rows: None,
            last_insert_id: None,
            row_count: rows.len(),
            rows,
            columns,
            rows_truncated: false,
        },
        outcome: crate::DependencyExchangeOutcome::Response,
        duration_ms: 1,
        parse_warnings: Vec::new(),
    }
}

fn mysql_column(
    name: &str,
    table: &str,
    column: &str,
    family: &str,
    sql_type: &str,
) -> MysqlColumn {
    MysqlColumn {
        database: None,
        name: name.to_string(),
        table: Some(table.to_string()),
        column: Some(column.to_string()),
        family: family.to_string(),
        sql_type: sql_type.to_string(),
        unsigned: None,
        bits: None,
        nullable: Some(false),
        scale: None,
        column_type_code: 0,
        flags: None,
    }
}
