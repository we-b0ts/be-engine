//! Case tail honors declared cache lifetime without inventing consumption.
use super::*;
use crate::replay::control::{ReplayControlRequest, begin_case, end_case};
use crate::replay::policy::test_fixture::{ManagedFixtureDirectory, managed_tempdir};
use crate::replay::{MysqlReplayConfig, ReplayExchangeStatus, ReplayRuntime};
use serde_json::json;
use std::time::Duration;

struct Fixture {
    _temp: ManagedFixtureDirectory,
    runtime: ReplayRuntime,
    cache: Uuid,
}
fn command(name: &str) -> ReplayControlRequest {
    ReplayControlRequest {
        command: name.into(),
        case_id: Some("case-a".into()),
        fail_on_dirty: false,
        fail_on_incomplete: false,
        identity_pairs: vec![],
        derived_input: None,
        native_event: None,
        input_timing: None,
        socketio_timing: None,
    }
}

async fn fixture(shared: bool, end_path: &str, captured_scope: bool) -> Fixture {
    let temp = managed_tempdir().unwrap();
    let root = temp.path().join("apis");
    let case = root.join("case-a");
    tokio::fs::create_dir_all(&case).await.unwrap();
    let cache = Uuid::new_v4();
    let completed = Uuid::new_v4();
    let body = |data: &str| {
        json!({"encoding":"utf8","data":data,"truncated":false,
        "original_len":data.len(),"stored_len":data.len()})
    };
    tokio::fs::write(
        temp.path().join("recording-run.json"),
        r#"{"status":"completed","run_id":"http-initialization-tail"}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(
        case.join("request.json"),
        json!({"method":"POST","uri":"/jobs","body":body("{}")}).to_string(),
    )
    .await
    .unwrap();
    tokio::fs::write(
        case.join("expected-response.json"),
        json!({"status":200,"headers":{},"body":body(r#"{"status":"queued"}"#)}).to_string(),
    )
    .await
    .unwrap();
    let event = |id: Uuid, path: &str| {
        json!({
            "event_type":"http_exchange","id":id,"scheme":"http","authority":"auth.test:80",
            "method":"POST","uri":path,"request_body":body("{}"),
            "response_status":200,"response_body":body("ok"),"response_headers":{},
            "request_started_at":"2020-01-01T00:00:00Z", "timestamp":"2020-01-01T00:00:00Z",
            "duration_ms":0,"outcome":"response","error":null
        })
    };
    tokio::fs::write(
        case.join("dependencies.jsonl"),
        format!(
            "{}\n{}\n",
            event(cache, "/cached"),
            event(completed, "/submit")
        ),
    )
    .await
    .unwrap();
    let mut observation = json!({
        "version":2,"request_timeout_ms":500,"end_reason":"resource",
        "capture_complete":true,"business_complete":true,"business_completion":"observed","inventory_complete":true,"source_stop_required":false,
        "cleanup_refs":[],"completed_refs":[
            {"protocol":"http","exchange_id":cache},
            {"protocol":"http","exchange_id":completed}
        ]
    });
    if captured_scope {
        observation["api"] = json!("POST /jobs");
        observation["scenario_index"] = json!(0);
        observation["resource_index"] = json!(0);
    }
    tokio::fs::write(
        case.join("async-api-observation.json"),
        observation.to_string(),
    )
    .await
    .unwrap();
    let cache_rule = if shared {
        "localcache:\n  requests:\n    - http: {host: auth.test, method: POST, path: /cached}\n"
    } else {
        ""
    };
    let policy = temp.path().join("policy.yaml");
    tokio::fs::write(&policy,format!("format: traffic-policy/v3\n{cache_rule}async_api:\n  POST /jobs:\n    - when_response: {{/status: queued}}\n      end:\n        - http: {{method: POST, endpoint: 'auth.test:80', path: {end_path}}}\n    - when_response: {{/status: other}}\n      end:\n        - http: {{method: POST, endpoint: 'auth.test:80', path: /cached}}\n  POST /refresh:\n    end:\n      - http: {{method: POST, endpoint: 'auth.test:80', path: /cached}}\n")).await.unwrap();
    crate::replay::write_test_recording_network_manifest(&root);
    let runtime = ReplayRuntime::load(
        MysqlReplayConfig {
            case_dir: root,
            selected_case_ids: vec![],
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            fake_cidr: "198.18.0.0/15".into(),
            report_path: None,
            session_path: None,
            control_socket_path: None,
            ca_cert_path: Some(temp.path().join("ca.pem")),
            ca_key_path: Some(temp.path().join("ca-key.pem")),
            policy_path: Some(policy),
            http_ignore_query_params: vec![],
            process_owned_dependencies: vec![],
            allowed_unused_http: None,
        },
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        begin_case(&command("begin"), runtime.state.clone()).await["ok"],
        true
    );
    // The non-cache completion is independently finished in this unit fixture;
    // the decision under test concerns only the still-unused initialization.
    runtime
        .state
        .lock()
        .await
        .protocols
        .http_exchanges
        .iter_mut()
        .find(|x| x.record.id.as_deref() == Some(&completed.to_string()))
        .unwrap()
        .status = ReplayExchangeStatus::Consumed;
    Fixture {
        _temp: temp,
        runtime,
        cache,
    }
}

fn index(state: &ReplayState, cache: Uuid) -> usize {
    state
        .protocols
        .http_exchanges
        .iter()
        .position(|x| x.record.id.as_deref() == Some(&cache.to_string()))
        .unwrap()
}

#[tokio::test]
async fn shared_http_permission_does_not_waive_the_case_actual_inventory() {
    let fixture = fixture(true, "/submit", true).await;
    let ended = tokio::time::timeout(
        Duration::from_secs(1),
        end_case(&command("end"), fixture.runtime.state.clone()),
    )
    .await
    .unwrap();
    assert_eq!(ended["ok"], false, "{ended}");
    let state = fixture.runtime.state.lock().await;
    let exchange = &state.protocols.http_exchanges[index(&state, fixture.cache)];
    assert_eq!(exchange.source, ReplaySource::Case);
    assert_eq!(exchange.status, ReplayExchangeStatus::Available);
    assert!(exchange.shared_origin.is_some());
    assert_eq!(
        state.unused_http_exchanges(ReplaySource::Case, false).len(),
        1
    );
    assert_eq!(
        state
            .unused_http_exchanges(ReplaySource::Startup, false)
            .len(),
        1
    );
    assert!(state.active_case_id.is_none());
    assert!(state.dependency_tails.failure("case-a").is_some());
}

#[tokio::test]
async fn unshared_or_explicit_completion_http_cannot_be_omitted() {
    for (shared, path, captured) in [
        (false, "/submit", true),
        (true, "/cached", true),
        (true, "/submit", false),
    ] {
        let fixture = fixture(shared, path, captured).await;
        let ended = tokio::time::timeout(
            Duration::from_secs(2),
            end_case(&command("end"), fixture.runtime.state.clone()),
        )
        .await
        .unwrap();
        assert_eq!(ended["ok"], false, "{ended}");
        let state = fixture.runtime.state.lock().await;
        assert!(state.active_case_id.is_none());
        assert!(state.dependency_tails.failure("case-a").is_some());
        assert_eq!(
            state.http_exchange_status(index(&state, fixture.cache)),
            Some(ReplayExchangeStatus::Available)
        );
    }
}

#[tokio::test]
async fn started_shared_http_still_waits_for_real_completion() {
    for status in [
        ReplayExchangeStatus::Responding,
        ReplayExchangeStatus::AwaitingClientTermination,
    ] {
        let fixture = fixture(true, "/submit", true).await;
        let state = fixture.runtime.state.clone();
        let at = {
            let mut s = state.lock().await;
            let at = index(&s, fixture.cache);
            s.protocols.http_exchanges[at].status = status;
            at
        };
        let end_state = state.clone();
        let ending = tokio::spawn(async move { end_case(&command("end"), end_state).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!ending.is_finished());
        assert_eq!(state.lock().await.active_case_id.as_deref(), Some("case-a"));
        state.lock().await.protocols.http_exchanges[at].status = ReplayExchangeStatus::Consumed;
        let ended = tokio::time::timeout(Duration::from_secs(1), ending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ended["ok"], true, "{ended}");
    }
}

#[tokio::test]
async fn failed_or_unproven_global_http_is_not_a_cache_hit() {
    let fixture = fixture(true, "/submit", true).await;
    {
        let mut state = fixture.runtime.state.lock().await;
        let at = index(&state, fixture.cache);
        let origin = state.protocols.http_exchanges[at].shared_origin.take();
        assert!(!state.http_shared_initialization(at, &[]));
        state.protocols.http_exchanges[at].shared_origin = origin;
        state.protocols.http_exchanges[at].status = ReplayExchangeStatus::Failed;
        // Actual HTTP transport failure also records the independent dirty
        // observation for the active Target case, including shared inputs.
        state
            .protocols
            .http_events
            .dirty_case_ids
            .insert("case-a".into());
    }
    let mut ending = command("end");
    ending.fail_on_dirty = true;
    let ended = end_case(&ending, fixture.runtime.state.clone()).await;
    assert_eq!(ended["ok"], false, "{ended}");
    let state = fixture.runtime.state.lock().await;
    assert_eq!(
        state.http_exchange_status(index(&state, fixture.cache)),
        Some(ReplayExchangeStatus::Failed)
    );
}
