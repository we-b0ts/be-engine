use super::*;
use crate::{AppConfig, config::BackgroundDependencyRuleConfig, recorder::CaseContext};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;
use traffic_model::trace::OutputKind;
use traffic_protocol::capture::{CaptureEvidence, CaptureFacts};
use traffic_protocol::connection::Endpoint;
use uuid::Uuid;

#[derive(Serialize)]
#[serde(transparent)]
struct Notification(Value);

impl CaptureEvidence for Notification {
    fn event_type(&self) -> &'static str {
        "redis_pub_sub_push"
    }

    fn capture_facts(&self) -> CaptureFacts {
        let reference = ProtocolRef::new(
            "redis",
            json!({
                "exchange_id": self.0["id"],
                "after": ProtocolRef::connection("redis", Uuid::nil(), 1),
            }),
        )
        .unwrap();
        CaptureFacts::dependency(reference, "delivery", true)
    }
}

#[tokio::test]
async fn native_process_notification_does_not_hold_an_active_case_open() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut config = AppConfig::default();
    config.recording.output_dir = directory.path().join("recordings");
    config.http_gateway.enabled = false;
    config.tls.ca_cert_path = directory.path().join("ca.pem");
    config.tls.ca_key_path = directory.path().join("ca-key.pem");
    config.process_owned_dependencies = vec![BackgroundDependencyRuleConfig::RedisPubsub {
        name: "subscriber-rule".into(),
        selector: serde_json::from_value(json!({
            "resource": {"protocol":"redis", "endpoint":"cache.test:6379", "database":0},
            "channel": "socketio",
            "kind": "message",
        }))?,
        source_revision: String::new(),
        source_evidence: String::new(),
    }];
    config
        .process_dependency_tasks
        .insert("subscriber-rule".into(), "socket-listener".into());
    let state = AppState::new_with_providers(config, crate::protocols::default_providers()).await?;
    state.close_bootstrap("test ready").await?;
    let host = Host {
        state: state.clone(),
        protocol: DependencyProtocol::Redis,
        info: ConnectionInfo {
            endpoint: Endpoint {
                host: "cache.test".into(),
                port: 6379,
            },
            client_addr: None,
            upstream_addr: None,
            max_frame_bytes: 1024,
        },
        transport: CaptureTransport::default(),
    };
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "active".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    let response = crate::redis::encode_array(&[b"message".as_slice(), b"socketio", b"input"]);
    let event = CaptureSnapshot::capture(&Notification(json!({
        "id": Uuid::new_v4(),
        "target_host": "cache.test",
        "target_port": 6379,
        "database": 0,
        "connection_id": Uuid::nil(),
        "subscription_sequence": 1,
        "timestamp": chrono::Utc::now(),
        "duration_ms": 1,
        "replay_safe": true,
        "response": crate::recorder::capture_body(&response, 1024),
    })))?;
    let pending = host.begin_message(&event).await?.unwrap();
    assert_eq!(
        state
            .inner
            .active_cases
            .drain_case_dependencies(case.id, Duration::ZERO, Duration::from_millis(50))
            .await,
        crate::active_case::DependencyDrainResult::Drained,
    );
    pending.prepare_output(OutputKind::End)?.commit();
    pending.complete(event).await?;
    drop(guard);
    state.recorder().finish_run().await?;
    let run = &state.recorder().run_dir;
    assert!(crate::dependency_index::recording::has_separated_messages(
        run
    )?);
    let report: Value = serde_json::from_slice(&std::fs::read(run.join("recording-run.json"))?)?;
    assert_eq!(report["status"], "completed");
    for path in [
        "indexes/startup-dependencies",
        "indexes/process-dependencies",
        "indexes/unattributed-dependencies",
        ".global-report-preparation.json",
    ] {
        assert!(!run.join(path).exists(), "unexpected preparation: {path}");
    }
    let path = run.join("indexes/process-scope.json");
    let bytes = crate::dependency_index::scoped::read_bytes(&path)?;
    let record: Value = serde_json::from_slice(&bytes)?;
    let capture = &record["capture"];
    assert_eq!(capture["attribution"]["source_task"], "socket-listener");
    assert_eq!(capture["observed_case"], case.id.to_string());
    assert!(capture["admitted_case"].is_null());
    Ok(())
}

#[tokio::test]
async fn session_notification_is_available_before_its_wire_output_attempt() -> Result<()> {
    use traffic_model::session::SessionEvent;

    let directory = tempfile::tempdir()?;
    let mut config = AppConfig::default();
    config.recording.output_dir = directory.path().join("recordings");
    config.recording.session_events = true;
    config.http_gateway.enabled = false;
    config.tls.ca_cert_path = directory.path().join("ca.pem");
    config.tls.ca_key_path = directory.path().join("ca-key.pem");
    let state = AppState::new_with_providers(config, crate::protocols::default_providers()).await?;
    state.session_event(SessionEvent::SourceStart)?;
    state.session_event(SessionEvent::Ready)?;
    let endpoint = Endpoint {
        host: "cache.test".into(),
        port: 6379,
    };
    let host = Host {
        state: state.clone(),
        protocol: DependencyProtocol::Redis,
        info: ConnectionInfo {
            endpoint,
            client_addr: None,
            upstream_addr: None,
            max_frame_bytes: 1024,
        },
        transport: CaptureTransport::default(),
    };
    let response = crate::redis::encode_array(&[b"message".as_slice(), b"socketio", b"input"]);
    let event = CaptureSnapshot::capture(&Notification(json!({
        "id": Uuid::new_v4(),
        "target_host": "cache.test",
        "target_port": 6379,
        "database": 0,
        "connection_id": Uuid::nil(),
        "subscription_sequence": 1,
        "timestamp": chrono::Utc::now(),
        "duration_ms": 1,
        "replay_safe": true,
        "response": crate::recorder::capture_body(&response, 1024),
    })))?;
    let pending = host
        .begin_message(&event)
        .await?
        .context("missing notification admission")?;
    let sequence = pending
        .dependency_id()
        .context("missing notification sequence")?;
    pending.stage_output(event, OutputKind::End).await?.commit();
    state.session_event(SessionEvent::Stop)?;
    state.session_event(SessionEvent::SourceExit { status: Some(0) })?;
    state.recorder().finish_run().await?;
    let root = &state.recorder().run_dir;
    let timeline = std::fs::read_to_string(root.join(traffic_recording_store::session::FILE))?;
    let kinds = timeline
        .lines()
        .filter_map(|row| row.split('\t').nth(2))
        .collect::<Vec<_>>();
    assert!(kinds.windows(4).any(|rows| rows
        == [
            "message_started",
            "notification",
            "wire_output_started",
            "wire_output"
        ]));
    assert_eq!(
        traffic_recording_store::session_records::dependency(root, sequence)?["event_type"],
        "redis_pub_sub_push"
    );
    Ok(())
}
