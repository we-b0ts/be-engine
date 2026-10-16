mod finalization_tests {
    use super::*;

    #[tokio::test]
    async fn finalize_without_completeness_gate_persists_false_for_pending_and_active_cases() {
        for active in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let collection_dir = temp.path().join("api-items");
            for case_id in ["case-a", "case-b"] {
                let case = collection_dir.join(case_id);
                tokio::fs::create_dir_all(&case).await.unwrap();
                tokio::fs::write(case.join("dependencies.jsonl"), "")
                    .await
                    .unwrap();
            }
            let session_path = temp.path().join("session.json");
            let report_path = temp.path().join("report.json");
            let (_address, tasks) = spawn_replay_with_control(
                &collection_dir,
                Some(report_path.clone()),
                session_path.clone(),
                temp.path().join("control.sock"),
            )
            .await;
            run_control(&session_path, "wait_ready", None, false)
                .await
                .unwrap();
            if active {
                run_control(&session_path, "begin", Some("case-a"), false)
                    .await
                    .unwrap();
            }

            let response =
                run_control_with_gates(&session_path, "finalize", None, false, false)
                    .await
                    .unwrap();
            let persisted: Value =
                serde_json::from_slice(&tokio::fs::read(&report_path).await.unwrap())
                    .unwrap();

            assert_eq!(response["complete"], false);
            assert_eq!(persisted["complete"], false);
            assert_eq!(persisted["finalized"], true);
            assert!(!persisted["finalized_at"].is_null());
            assert_eq!(persisted["cases"].as_array().unwrap().len(), 2);
            assert_eq!(persisted["active_case_id"] == "case-a", active);
            abort_tasks(tasks);
        }
    }
}
