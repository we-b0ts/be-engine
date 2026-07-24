use chrono::{DateTime, Utc};
use hyper::Uri;
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::recorder::CaseContext;
use crate::{ActiveCaseGuard, ActiveCaseRejection, AppState};

pub(super) async fn try_admit_case(
    state: &AppState,
    case: &CaseContext,
    case_pattern: &str,
    max_cases: usize,
    upstream_base: &str,
    uri: &Uri,
) -> Option<ActiveCaseGuard> {
    let published_cases = state.recorder().published_case_count(case).await;
    if published_cases >= max_cases {
        info!(
            reason = "case_limit_reached",
            rule = %case.rule_name,
            case_pattern,
            published_cases,
            max_cases,
            uri = %uri,
            "HTTP gateway matched request sent to fallback"
        );
        return None;
    }

    match state.try_register_active_case(case.clone()) {
        Ok(guard) => {
            let admission = CaseAdmissionRecord {
                timestamp: Utc::now(),
                case_id: case.id,
                rule_name: case.rule_name.clone(),
                uri_group: case.uri_group.clone(),
                case_pattern: case_pattern.to_string(),
                uri: uri.to_string(),
                upstream: upstream_base.to_string(),
            };
            if let Err(err) = state
                .recorder()
                .write_case_json(case, "admission.json", &admission)
                .await
            {
                warn!(
                    error = %err,
                    case_id = %case.id,
                    "failed to persist HTTP gateway case admission"
                );
                return None;
            }
            info!(
                case_id = %case.id,
                rule = %case.rule_name,
                case_pattern,
                upstream = %upstream_base,
                "registered active HTTP gateway case"
            );
            Some(guard)
        }
        Err(reason) => {
            info!(
                reason = active_case_rejection_reason(reason),
                rule = %case.rule_name,
                case_pattern,
                uri = %uri,
                "HTTP gateway matched request sent to fallback"
            );
            None
        }
    }
}

#[derive(Serialize)]
struct CaseAdmissionRecord {
    timestamp: DateTime<Utc>,
    case_id: Uuid,
    rule_name: String,
    uri_group: Option<String>,
    case_pattern: String,
    uri: String,
    upstream: String,
}

fn active_case_rejection_reason(reason: ActiveCaseRejection) -> &'static str {
    match reason {
        ActiveCaseRejection::NotReady => "not_ready",
        ActiveCaseRejection::Busy => "busy",
        ActiveCaseRejection::Quiescing => "quiescing",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;
    use crate::config::AppConfig;

    #[tokio::test]
    async fn quiescing_stops_new_case_admission_and_drains_the_active_case() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.mysql.enabled = false;
        config.recording.output_dir = temp.path().join("recordings");
        config.recording.shutdown_case_drain_timeout_ms = 1_000;
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();
        let uri = "/api/resource/isok".parse().unwrap();
        let first = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "record-api".to_string(),
            uri_group: Some("api-resource-isok".to_string()),
        };
        let guard = try_admit_case(
            &state,
            &first,
            "/api/resource/isok",
            50,
            "http://127.0.0.1:7171",
            &uri,
        )
        .await
        .unwrap();

        assert!(state.begin_case_quiescing());
        assert_eq!(state.recording_lifecycle_phase(), "quiescing");
        let second = CaseContext {
            id: Uuid::new_v4(),
            ..first
        };
        assert!(
            try_admit_case(
                &state,
                &second,
                "/api/resource/isok",
                50,
                "http://127.0.0.1:7171",
                &uri,
            )
            .await
            .is_none()
        );

        let drain = {
            let state = state.clone();
            tokio::spawn(async move { state.wait_for_active_case_shutdown_drain().await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!drain.is_finished());
        drop(guard);
        assert!(drain.await.unwrap());
    }
}
