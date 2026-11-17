//! Only a Case running at shutdown admission supplies mechanical association.
use super::*;
use crate::{AppConfig, AppState, recorder::CaseContext};

#[tokio::test]
async fn associated_shutdown_bypasses_analysis_but_idle_shutdown_requires_it() {
    for associated in [false, true] {
        let target = crate::rewrite::worker::tests::configured_target();
        fs::write(target.path().join(".traffic-e2e/policy.yaml"), POLICY).unwrap();
        let mut config = AppConfig::default();
        config.recording.output_dir = target.path().join(".traffic-e2e/local/recordings");
        config.tls.ca_cert_path = target.path().join("ca.pem");
        config.tls.ca_key_path = target.path().join("ca-key.pem");
        config.http_gateway.enabled = false;
        let app = AppState::new(config).await.unwrap();
        app.close_bootstrap("ready").await.unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "source".into(),
            uri_group: None,
        };
        let guard = app.try_reserve_active_case(case.clone()).unwrap();
        guard.activate_dependencies().unwrap();
        if associated {
            app.inner.active_cases.close_admission();
        }
        drop(guard);
        app.inner.active_cases.close_admission();
        app.recorder()
            .write_case_json(&case, "admission.json", &json!({"case_id":case.id}))
            .await
            .unwrap();
        app.recorder()
            .fail_case(
                &case,
                "shutdown_case_drain_timeout",
                "original incomplete primary",
            )
            .await
            .unwrap();
        let event = http("/cleanup");
        let RecorderEvent::HttpExchange(exchange) = &event else {
            unreachable!()
        };
        let targets = app.capture_dependency_start(
            crate::dependency::observation::ProtocolRef::exchange("http", exchange.id),
        );
        app.record_event_for_targets(event, targets);
        app.recorder().finish_run().await.unwrap();
        let mut state = crate::rewrite::test_support::test_state();
        state.case_source = Some(app.recorder().run_dir.as_ref().clone());
        state.recording_run_id = app
            .recorder()
            .run_dir
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .into();
        state.source_revision =
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        let context = dependency_attribution_context(super::super::super::RewriteContext {
            target_root: target.path().into(),
        })
        .unwrap();
        assert_eq!(
            context.unattributed_exchange_ids.len(),
            usize::from(!associated)
        );
        assert_eq!(
            analysis::required_action(target.path(), &state).is_some(),
            !associated
        );
        let source = source::load(&state).unwrap();
        assert!(
            source.exchanges.values().all(|event| event.capture.phase
                == crate::dependency::observation::CapturePhase::Shutdown)
        );
        assert_eq!(source.exchanges.len(), 1);
        if associated {
            assert!(
                matches!(source.exchanges.values().next().unwrap().capture.attribution,
                DependencyOwner::Shutdown { origin_case_id, .. } if origin_case_id == case.id)
            );
        }
    }
}
