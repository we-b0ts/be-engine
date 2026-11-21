//! Durable shutdown diagnostics, independent of primary case publication.

impl super::Recorder {
    pub async fn retain_shutdown_failure(
        &self,
        case_id: uuid::Uuid,
        failure: super::CaseInvalidation,
    ) {
        self.run_state
            .lock()
            .await
            .shutdown_failures
            .entry(case_id)
            .or_insert(failure);
    }
    pub async fn write_shutdown_report(&self, report: &serde_json::Value) -> anyhow::Result<()> {
        super::run::write_pretty_json(&self.run_dir.join("recording-shutdown.json"), report).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CaseContext, CaseInvalidation, Recorder};
    use uuid::Uuid;

    #[tokio::test]
    async fn unfinished_staging_keeps_its_shutdown_cause_when_no_finalizer_returns() {
        let temp = tempfile::tempdir().unwrap();
        let recorder = Recorder::new(temp.path()).await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "shutdown".into(),
            uri_group: None,
        };
        recorder
            .write_case_json(
                &case,
                "admission.json",
                &serde_json::json!({"case_id": case.id}),
            )
            .await
            .unwrap();
        recorder
            .retain_shutdown_failure(
                case.id,
                CaseInvalidation::new(
                    "shutdown_case_drain_timeout",
                    "shutdown truncated this case",
                ),
            )
            .await;
        recorder.finish_run().await.unwrap();
        let detail: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(recorder.case_failed_dir(&case).join("recording-error.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(detail["reason"], "shutdown_case_drain_timeout");
        assert_eq!(detail["message"], "shutdown truncated this case");
        let manifest: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(recorder.run_dir.join("recording-run.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["failed_cases"], 1);
        assert_eq!(manifest["published_cases"], 0);
    }
}
