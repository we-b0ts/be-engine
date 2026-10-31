use super::tests::{GET, client, command, fixture};
use super::*;
use crate::replay::control::{begin_case, end_case};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn source_request(root: &std::path::Path) {
    tokio::fs::write(
        root.join("case-a/request.json"),
        json!({
            "method":"POST","uri":"/api/v1/responses",
            "body":{"encoding":"utf8","data":"{\"background\":true}","truncated":false}
        })
        .to_string(),
    )
    .await
    .unwrap();
    tokio::fs::write(root.join("case-a/expected-response.json"), b"{}")
        .await
        .unwrap();
}

#[tokio::test]
async fn primary_failure_skips_success_work_but_preserves_the_target_stop_receipt() {
    let fixture = fixture(Some(900_000), 1).await;
    let path = fixture.root.join("case-a/api-origin-observation.json");
    let legacy: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    tokio::fs::remove_file(path).await.unwrap();
    tokio::fs::write(
        fixture.root.join("case-a/async-api-observation.json"),
        json!({
            "version":2,"capture_complete":true,"business_complete":false,"business_completion":"unobserved","inventory_complete":true,
            "end_reason":"timeout","request_timeout_ms":900_000,
            "source_stop_required":true,"source_stop_after_ms":800_000,"cleanup_refs":[],
            "completed_refs":legacy["selected_completed_refs"]
        })
        .to_string(),
    )
    .await
    .unwrap();
    let state = fixture.runtime.state.clone();
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let mark = crate::replay::control::handle_control_request(
        command("case_failed"),
        state.clone(),
        None,
        None,
    )
    .await
    .0;
    assert_eq!(mark["ok"], true);
    assert_eq!(end_case(&command("end"), state.clone()).await["ok"], false);
    assert_eq!(
        end_case(&command("end_stopped"), state.clone()).await["ok"],
        false
    );
    let prepared = tokio::time::timeout(
        Duration::from_secs(1),
        crate::replay::control::handle_control_request(
            command("prepare_end"),
            state.clone(),
            None,
            None,
        ),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(prepared["ok"], true, "{prepared}");
    assert_eq!(
        end_case(&command("end_stopped"), state.clone()).await["ok"],
        true
    );
    assert!(state.lock().await.target_session_stopped);
    assert!(state.lock().await.active_case_id.is_none());
    assert_eq!(state.lock().await.redis.snapshot().unused_case.len(), 1);
}

#[tokio::test]
async fn async_observation_retains_case_until_real_target_consumes_its_finite_tail() {
    for reason in ["resource", "dependency_failure", "timeout"] {
        let expected: &[u8] = if reason == "dependency_failure" {
            b"-ERR unavailable\r\n"
        } else {
            b"+OK\r\n"
        };
        let fixture = super::tests::fixture_with_response(
            Some(1000),
            1,
            (reason == "dependency_failure").then_some(("error", "-ERR unavailable\r\n")),
        )
        .await;
        let path = fixture.root.join("case-a/api-origin-observation.json");
        let legacy: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        tokio::fs::remove_file(path).await.unwrap();
        tokio::fs::write(
            fixture.root.join("case-a/async-api-observation.json"),
            json!({
                "version":2,"capture_complete":true,"business_complete":reason=="resource","business_completion":if reason=="resource" {"observed"}else{"unobserved"},"inventory_complete":true,
                "end_reason":reason,"request_timeout_ms":1000,
                "source_stop_required":reason!="resource",
                "source_stop_after_ms":(reason!="resource").then_some(0),"cleanup_refs":[],
                "completed_refs":legacy["selected_completed_refs"]
            })
            .to_string(),
        )
        .await
        .unwrap();
        let state = fixture.runtime.state.clone();
        let began = begin_case(&command("begin"), state.clone()).await;
        assert_eq!(began["ok"], true, "{reason}: {began}");
        let requires_stop = reason != "resource";
        assert_eq!(
            begin_case(&command("begin"), state.clone()).await["target_stop_required"],
            requires_stop
        );
        if requires_stop {
            assert_eq!(end_case(&command("end"), state.clone()).await["ok"], false);
            assert_eq!(
                end_case(&command("end_stopped"), state.clone()).await["ok"],
                false
            );
            assert_eq!(state.lock().await.active_case_id.as_deref(), Some("case-a"));
        }
        let prepared = Arc::new(tokio::sync::Notify::new());
        let stopped = Arc::new(tokio::sync::Notify::new());
        let end_state = state.clone();
        let prepare_signal = prepared.clone();
        let stop_signal = stopped.clone();
        let ending = tokio::spawn(async move {
            if requires_stop {
                let ready = crate::replay::control::target_stop::prepare(
                    &command("prepare_end"),
                    &end_state,
                )
                .await;
                assert_eq!(ready["ok"], true, "{ready}");
                prepare_signal.notify_one();
                stop_signal.notified().await;
                end_case(&command("end_stopped"), end_state).await
            } else {
                end_case(&command("end"), end_state).await
            }
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !ending.is_finished(),
            "primary response cannot discharge async work"
        );
        let (mut client, task) = client(state.clone()).await;
        client.write_all(GET).await.unwrap();
        let mut response = vec![0; expected.len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, expected);
        if requires_stop {
            tokio::time::timeout(Duration::from_millis(500), prepared.notified())
                .await
                .unwrap();
            assert_eq!(state.lock().await.active_case_id.as_deref(), Some("case-a"));
            client.shutdown().await.unwrap();
            task.await.unwrap().unwrap();
            stopped.notify_one();
        } else {
            client.shutdown().await.unwrap();
            task.await.unwrap().unwrap();
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), ending)
                .await
                .unwrap()
                .unwrap()["ok"],
            true
        );
        let report = state.lock().await.snapshot_report();
        assert_eq!(
            report
                .case_execution_failures
                .iter()
                .any(|failure| failure["kind"] == "source_business_incomplete"),
            requires_stop
        );
        if requires_stop {
            assert!(
                report.is_dirty(),
                "a captured Source timeout/failure cannot certify declared business completion"
            );
        }
        if requires_stop {
            let mut next = command("begin");
            next.case_id = Some("case-b".into());
            assert_eq!(begin_case(&next, state.clone()).await["ok"], false);
        }
    }
}

#[tokio::test]
async fn old_complete_source_can_prove_async_tail_but_an_unproven_end_cannot_release_it() {
    let fixture = super::tests::fixture(None, 1).await;
    source_request(&fixture.root).await;
    let rule = serde_json::from_value(
        json!({"when":{"/background":true},"end":[{"redis":{"operation":"GET","key":"key"}}]}),
    )
    .unwrap();
    let state = fixture.runtime.state.clone();
    state
        .lock()
        .await
        .dependency_tails
        .async_rules
        .insert("POST /api/v1/responses".into(), rule);
    state.lock().await.dependency_tails.request_timeout = Duration::from_millis(1000);
    assert_eq!(
        begin_case(&command("begin"), state.clone()).await["ok"],
        true
    );
    let end_state = state.clone();
    let ending = tokio::spawn(async move { end_case(&command("end"), end_state).await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(!ending.is_finished());
    let (mut client, task) = client(state.clone()).await;
    client.write_all(GET).await.unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(ending.await.unwrap()["ok"], true);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();

    let fixture = super::tests::fixture(None, 1).await;
    source_request(&fixture.root).await;
    let rule=serde_json::from_value(json!({"when":{"/background":true},"end":[{"redis":{"operation":"DEL","key":"missing","occurrence":2}}]})).unwrap();
    fixture
        .runtime
        .state
        .lock()
        .await
        .dependency_tails
        .async_rules
        .insert("POST /api/v1/responses".into(), rule);
    let result = begin_case(&command("begin"), fixture.runtime.state.clone()).await;
    assert_eq!(result["ok"], false);
    assert!(
        result["error"]
            .as_str()
            .unwrap()
            .contains("no proven completion")
    );
}

#[tokio::test]
async fn incomplete_async_inventory_rejects_activation_for_all_end_reasons() {
    for reason in ["resource", "dependency_failure", "timeout"] {
        let fixture = fixture(None, 1).await;
        tokio::fs::write(
            fixture.root.join("case-a/async-api-observation.json"),
            json!({
                "version":2,"capture_complete":true,"business_complete":reason=="resource","business_completion":if reason=="resource" {"observed"}else{"unobserved"},"inventory_complete":false,"end_reason":reason,
                "request_timeout_ms":1000,"completed_refs":[]
            })
            .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(
            begin_case(&command("begin"), fixture.runtime.state.clone()).await["ok"],
            false
        );
    }
}

#[tokio::test(start_paused = true)]
async fn only_deadline_completion_waits_for_the_source_stop_clock() {
    for reason in ["resource", "dependency_failure", "timeout"] {
        let fixture = fixture(None, 1).await;
        tokio::fs::write(
            fixture.root.join("case-a/async-api-observation.json"),
            json!({
                "version":2,"capture_complete":true,"business_complete":reason=="resource","business_completion":if reason=="resource" {"observed"}else{"unobserved"},"inventory_complete":true,"end_reason":reason,
                "request_timeout_ms":100,"source_stop_required":true,
                "source_stop_after_ms":100,"cleanup_refs":[],"completed_refs":[]
            })
            .to_string(),
        )
        .await
        .unwrap();
        let state = fixture.runtime.state.clone();
        assert_eq!(
            begin_case(&command("begin"), state.clone()).await["ok"],
            true
        );
        let started = Instant::now();
        prepare_target_stop(&state, "case-a").await.unwrap();
        assert_eq!(
            started.elapsed(),
            if reason == "timeout" {
                Duration::from_millis(100)
            } else {
                Duration::ZERO
            }
        );
        let prepared_deadline = {
            let locked = state.lock().await;
            assert!(locked.async_case_quiescing());
            locked.async_cleanup_deadline("case-a").unwrap()
        };
        tokio::time::advance(Duration::from_millis(20)).await;
        prepare_target_stop(&state, "case-a").await.unwrap();
        assert_eq!(
            state.lock().await.async_cleanup_deadline("case-a"),
            Some(prepared_deadline),
            "repeated preparation cannot renew the cleanup deadline"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn confirmed_target_stop_skips_attribution_idle_for_plain_and_interaction_cases() {
    for interaction in [false, true] {
        let fixture = super::tests::fixture_empty().await;
        source_request(&fixture.root).await;
        if interaction {
            let path = fixture.root.join("case-a/request.json");
            let mut request: serde_json::Value =
                serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
            request["interaction"] =
                serde_json::to_value(crate::interaction::model::InputTranscript::new(
                    crate::interaction::model::Protocol::Sse,
                    crate::interaction::policy::InteractionPolicy::default(),
                ))
                .unwrap();
            tokio::fs::write(path, request.to_string()).await.unwrap();
        }
        tokio::fs::write(
            fixture.root.join("case-a/async-api-observation.json"),
            json!({"version":2,"capture_complete":true,"business_complete":true,"business_completion":"observed","inventory_complete":true,"end_reason":"resource",
                "request_timeout_ms":1000,"source_stop_required":true,"source_stop_after_ms":0,
                "cleanup_refs":[],"completed_refs":[]})
            .to_string(),
        )
        .await
        .unwrap();
        let state = fixture.runtime.state.clone();
        state.lock().await.case_dependency_post_response_window = Duration::from_secs(60);
        assert_eq!(
            begin_case(&command("begin"), state.clone()).await["ok"],
            true
        );
        assert_eq!(
            end_case(&command("end_stopped"), state.clone()).await["ok"],
            false,
            "the idle shortcut requires prior stop preparation"
        );
        assert_eq!(state.lock().await.active_case_id.as_deref(), Some("case-a"));
        prepare_target_stop(&state, "case-a").await.unwrap();
        let started = Instant::now();
        let response = end_case(&command("end_stopped"), state.clone()).await;
        assert_eq!(
            response["ok"], true,
            "interaction={interaction}: {response}"
        );
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "confirmed stop cannot add an attribution window or exhaust the fixed cleanup budget"
        );
        assert_eq!(state.lock().await.active_case_id, None);
    }
}
