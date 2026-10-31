//! A passive native client receives external input by its original request clock.
use super::*;
use crate::interaction::model::{
    InputAction, InputActionKind, InputTranscript, Protocol, WireMessage,
};
use crate::interaction::policy::InteractionPolicy;
use std::time::Duration;
mod active;
mod ambient;
mod delivery;
mod encryption;
mod guards;
mod heartbeats;
mod recording;
mod routing;
mod scale;
mod wire;

const CASE: &str = "00000000-0000-0000-0000-000000000123";
const START: &str = "2020-01-01T00:10:00Z";
const SUBSCRIBED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";

fn fixture(root: &Path) -> (Vec<Value>, Vec<u8>) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    let mut input = InputTranscript::new(Protocol::SocketIo, InteractionPolicy::default());
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: 0,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("40/chat,{}"),
        },
    });
    std::fs::write(
        root.join("case/request.json"),
        json!({"method":"GET","uri":"/socket.io/",
        "timestamp":START,"interaction":input})
        .to_string(),
    )
    .unwrap();
    // Completion metadata is the only permitted response input to preparation.
    // This deliberately unrelated expected value cannot become Redis input.
    std::fs::write(root.join("case/expected-response.json"), json!({"duration_ms":1500,
        "interaction":{"version":1,"protocol":"socket_io","events":[{"private":"NEVER_EXECUTE_EXPECTED"}],
        "end":{"clean":true,"reason":"business_idle","offset_ms":1500}}}).to_string()).unwrap();
    let subscriber = Uuid::new_v4();
    let value = json!({"method":"emit","event":"example:notice","data":[{"value":7}],
        "binary":false,"namespace":"/chat","room":"user:7","skip_sid":null,
        "callback":null,"host_id":SOURCE});
    let raw =
        crate::redis::encode_array(&[b"message", b"jobs", &serde_json::to_vec(&value).unwrap()]);
    let mut incoming = push(subscriber, None, &raw, 600_040);
    incoming["timestamp"] = "2020-01-01T00:10:00.040Z".into();
    (
        vec![
            exchange(subscriber, 1, "SUBSCRIBE", &[b"jobs"], SUBSCRIBED),
            incoming,
        ],
        raw,
    )
}

pub(super) async fn runtime(
    root: &Path,
    cases: &[Value],
    globals: &[Value],
    lazy: bool,
) -> Result<Arc<ReplayRuntime>> {
    recording::runtime(root, cases, globals, lazy).await
}

#[tokio::test]
async fn external_broadcast_uses_native_request_clock_instead_of_subscription_age() {
    for lazy in [false, true] {
        for policy in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let (globals, original) = fixture(temp.path());
            if policy {
                std::fs::create_dir_all(temp.path().join(".traffic-e2e")).unwrap();
                std::fs::write(
                    temp.path().join(".traffic-e2e/policy.yaml"),
                    "format: traffic-policy/v3\n",
                )
                .unwrap();
            }
            let runtime = runtime(temp.path(), &[], &globals, lazy).await.unwrap();
            let (mut subscriber, task) = connect(&runtime).await;
            assert_eq!(
                send(&mut subscriber, &[b"SUBSCRIBE", b"jobs"]).await,
                SUBSCRIBED
            );
            let begin =
                serde_json::from_value(json!({"command":"request_begin","case_id":CASE})).unwrap();
            let (reply, _) = crate::replay::control::handle_control_request(
                begin,
                runtime.state.clone(),
                None,
                None,
            )
            .await;
            assert_eq!(reply["ok"], true);
            let observe =
                serde_json::from_value(json!({"command":"native_event_begin","case_id":CASE}))
                    .unwrap();
            let (reply, _) = crate::replay::control::handle_control_request(
                observe,
                runtime.state.clone(),
                None,
                None,
            )
            .await;
            assert_eq!(reply["enabled"], true);
            let connected =
                serde_json::from_value(json!({"command":"native_connected","case_id":CASE,
        "native_event":{"epoch":reply["epoch"],"namespace":"/chat"}}))
                .unwrap();
            let (reply, _) = crate::replay::control::handle_control_request(
                connected,
                runtime.state.clone(),
                None,
                None,
            )
            .await;
            assert_eq!(reply["ok"], true);
            let received = tokio::time::timeout(
                Duration::from_millis(250),
                read_redis_frame(&mut subscriber),
            )
            .await;
            assert!(
                received.is_ok(),
                "external native input was left waiting for the ten-minute Source subscription age"
            );
            assert_eq!(received.unwrap().unwrap().unwrap().raw.to_vec(), original);
            guards::silent(&mut subscriber).await;
            assert_eq!(
                runtime
                    .state
                    .lock()
                    .await
                    .redis
                    .pubsub
                    .report()
                    .unwrap()
                    .delivered_pushes,
                1
            );
            task.abort();
        }
    }
}
