use chrono::{DateTime, Utc};
use hyper::Uri;
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::recorder::{CaseContext, PrimaryCaseDescriptor};
use crate::{ActiveCaseActivationError, ActiveCaseGuard, ActiveCaseRejection, AppState};

pub(super) async fn try_admit_case(
    state: &AppState,
    case: &CaseContext,
    descriptor: &PrimaryCaseDescriptor,
    recording_api: Option<&str>,
    max_cases: usize,
    upstream_base: &str,
    uri: &Uri,
) -> Option<ActiveCaseGuard> {
    let Some(case_pattern) = descriptor.http_path_pattern() else {
        warn!(
            case_id = %case.id,
            "HTTP gateway received a non-HTTP primary case descriptor"
        );
        return None;
    };
    let published_cases = match recording_api {
        Some(recording_api) => state
            .recorder()
            .published_recording_api_count(recording_api)
            .await
            .unwrap_or_default(),
        None => state.recorder().published_case_count(case).await,
    };
    if published_cases >= max_cases {
        info!(
            reason = "case_limit_reached",
            rule = %case.rule_name,
            case_pattern,
            recording_api,
            published_cases,
            max_cases,
            uri = %uri,
            "HTTP gateway matched request sent to fallback"
        );
        return None;
    }

    match state.try_reserve_active_case(case.clone()) {
        Ok(guard) => {
            if let Err(err) = state
                .seal_bootstrap_dependencies("HTTP gateway case admission")
                .await
            {
                warn!(
                    error = %err,
                    case_id = %case.id,
                    "failed to seal bootstrap dependencies before HTTP gateway case admission"
                );
                return None;
            }
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
                discard_unadmitted_case(state, case).await;
                return None;
            }
            if let Err(err) = state
                .recorder()
                .write_case_json(case, "case.json", descriptor)
                .await
            {
                warn!(
                    error = %err,
                    case_id = %case.id,
                    "failed to persist HTTP primary case descriptor"
                );
                discard_unadmitted_case(state, case).await;
                return None;
            }
            if let Err(reason) = state.activate_case_dependencies(&guard) {
                info!(
                    reason = active_case_activation_error(reason),
                    rule = %case.rule_name,
                    case_pattern,
                    "HTTP gateway case admission stopped before dependency activation"
                );
                discard_unadmitted_case(state, case).await;
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

async fn discard_unadmitted_case(state: &AppState, case: &CaseContext) {
    if let Err(error) = state.recorder().discard_unadmitted_case(case).await {
        warn!(
            %error,
            case_id = %case.id,
            "failed to discard unadmitted HTTP gateway case"
        );
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

fn active_case_activation_error(reason: ActiveCaseActivationError) -> &'static str {
    match reason {
        ActiveCaseActivationError::Quiescing => "quiescing",
        ActiveCaseActivationError::ReservationMissing => "reservation_missing",
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
            rule_name: "http-rule".to_string(),
            uri_group: Some("api-resource-isok".to_string()),
        };
        let guard = try_admit_case(
            &state,
            &first,
            &PrimaryCaseDescriptor::http("GET", "/api/resource/isok"),
            None,
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
                &PrimaryCaseDescriptor::http("GET", "/api/resource/isok"),
                None,
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

    #[tokio::test]
    async fn cancelled_admission_does_not_accept_dependencies_or_leave_staging() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.mysql.enabled = false;
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();
        assert!(state.close_bootstrap("test").await.unwrap());

        let dependency_write_lock = state.recorder().dependency_write_lock.clone();
        let write_guard = dependency_write_lock.lock().await;
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "http-rule".to_string(),
            uri_group: Some("api-resource-isok".to_string()),
        };
        let case_for_task = case.clone();
        let state_for_task = state.clone();
        let admission = tokio::spawn(async move {
            let uri = "/api/resource/isok".parse().unwrap();
            try_admit_case(
                &state_for_task,
                &case_for_task,
                &PrimaryCaseDescriptor::http("GET", "/api/resource/isok"),
                None,
                50,
                "http://127.0.0.1:7171",
                &uri,
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.inner.active_cases.case_slot_occupied() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(state.capture_dependency_targets().cases.is_empty());

        admission.abort();
        assert!(matches!(
            admission.await,
            Err(error) if error.is_cancelled()
        ));
        drop(write_guard);

        assert!(
            !tokio::fs::try_exists(state.recorder().case_staging_dir(&case))
                .await
                .unwrap()
        );
        assert!(!state.inner.active_cases.case_slot_occupied());
    }

    #[tokio::test]
    async fn cancelled_bootstrap_seal_is_retried_by_the_next_admission() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.mysql.enabled = false;
        config.recording.output_dir = temp.path().join("recordings");
        config.tls.ca_cert_path = temp.path().join("ca.pem");
        config.tls.ca_key_path = temp.path().join("ca-key.pem");
        let state = AppState::new(config).await.unwrap();

        let dependency_write_lock = state.recorder().dependency_write_lock.clone();
        let write_guard = dependency_write_lock.lock().await;
        let first = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "http-rule".to_string(),
            uri_group: Some("api-resource-isok".to_string()),
        };
        let first_for_task = first.clone();
        let state_for_task = state.clone();
        let first_admission = tokio::spawn(async move {
            let uri = "/api/resource/isok".parse().unwrap();
            try_admit_case(
                &state_for_task,
                &first_for_task,
                &PrimaryCaseDescriptor::http("GET", "/api/resource/isok"),
                None,
                50,
                "http://127.0.0.1:7171",
                &uri,
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.inner.active_cases.case_slot_occupied() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!state.inner.active_cases.is_bootstrap_open());
        assert!(!state.inner.active_cases.is_bootstrap_sealed());
        assert!(state.capture_dependency_targets().cases.is_empty());

        first_admission.abort();
        assert!(matches!(
            first_admission.await,
            Err(error) if error.is_cancelled()
        ));
        drop(write_guard);

        let second = CaseContext {
            id: Uuid::new_v4(),
            ..first
        };
        let uri = "/api/resource/isok".parse().unwrap();
        let second_guard = try_admit_case(
            &state,
            &second,
            &PrimaryCaseDescriptor::http("GET", "/api/resource/isok"),
            None,
            50,
            "http://127.0.0.1:7171",
            &uri,
        )
        .await
        .unwrap();
        assert!(state.inner.active_cases.is_bootstrap_sealed());
        assert_eq!(
            state.capture_dependency_targets().cases,
            vec![(second.clone(), "active_window")]
        );

        drop(second_guard);
        state
            .recorder()
            .discard_unadmitted_case(&second)
            .await
            .unwrap();
    }
}
