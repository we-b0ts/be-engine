//! A SID-directed emit is proved by live namespace identity, not a generic room format.
use super::*;
use crate::interaction::{
    model::{InputAction, InputActionKind, InputTranscript, Protocol, WireMessage},
    policy::InteractionPolicy,
};

const SOURCE_SID: &str = "sourceSID0123456789a";
const TARGET_SID: &str = "targetSID0123456";

fn payload(host: &str, room: &str) -> Value {
    json!({"method":"emit","event":"example:status","data":[{"stable":7}],
        "binary":false,"namespace":"/chat","room":room,"skip_sid":null,
        "callback":null,"host_id":host})
}

fn input(root: &Path) {
    std::fs::create_dir_all(root.join("case")).unwrap();
    std::fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
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
        "timestamp":"2020-01-01T00:10:00Z","interaction":input})
        .to_string(),
    )
    .unwrap();
    std::fs::write(root.join("case/expected-response.json"), json!({"interaction":{"version":1,
        "protocol":"socket_io","events":[{"message":WireMessage::text(format!("40/chat,{{\"sid\":\"{SOURCE_SID}\"}}"))}]}}).to_string()).unwrap();
    std::fs::write(root.join(".traffic-e2e/policy.yaml"),
        "format: traffic-policy/v3\njson:\n  fields:\n    /host_id: {kind: identity, formats: [{hex: 32}]}\n    /room: {kind: identity, formats: [string]}\n").unwrap();
}

async fn control(runtime: &Arc<ReplayRuntime>, value: Value) -> Value {
    crate::replay::control::handle_control_request(
        serde_json::from_value(value).unwrap(),
        runtime.state.clone(),
        None,
        None,
    )
    .await
    .0
}

#[tokio::test]
async fn actual_namespace_sid_admits_only_its_original_publish_and_keeps_business_rooms_strict() {
    for (lazy, formats) in [(false, false), (true, false), (false, true), (true, true)] {
        let temp = tempfile::tempdir().unwrap();
        input(temp.path());
        if !formats {
            std::fs::remove_file(temp.path().join(".traffic-e2e/policy.yaml")).unwrap();
        }
        let source = serde_json::to_vec(&payload(SOURCE, SOURCE_SID)).unwrap();
        let runtime = runtime(
            temp.path(),
            &[
                exchange(Uuid::new_v4(), 1, "PUBLISH", &[b"jobs", &source], b":1\r\n"),
                exchange(
                    Uuid::new_v4(),
                    1,
                    "PUBLISH",
                    &[
                        b"jobs",
                        &serde_json::to_vec(&payload(SOURCE, "user:7")).unwrap(),
                    ],
                    b":1\r\n",
                ),
            ],
            &[],
            lazy,
        )
        .await
        .unwrap();
        assert_eq!(
            control(
                &runtime,
                json!({"command":"request_begin","case_id":"case"})
            )
            .await["ok"],
            true
        );
        let observation = control(
            &runtime,
            json!({"command":"native_event_begin","case_id":"case"}),
        )
        .await;
        assert_eq!(
            observation["enabled"], true,
            "identity observation is needed even without notification slots"
        );
        let (mut client, mut task) = connect(&runtime).await;
        let actual = payload(TARGET, TARGET_SID);
        send_unmatched(
            &mut client,
            &[b"PUBLISH", b"jobs", &serde_json::to_vec(&actual).unwrap()],
        )
        .await;
        reconnect(&runtime, &mut client, &mut task).await;
        assert_eq!(
            control(
                &runtime,
                json!({"command":"native_connected","case_id":"case",
            "native_event":{"epoch":observation["epoch"],"namespace":"/chat","sid":TARGET_SID}})
            )
            .await["ok"],
            true
        );
        for (pointer, value) in [
            ("/room", json!("another-sid")),
            ("/namespace", json!("/other")),
            ("/data/0/stable", json!(8)),
            ("/callback", json!([TARGET_SID, "/chat", 1])),
        ] {
            let mut bad = actual.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            send_unmatched(
                &mut client,
                &[b"PUBLISH", b"jobs", &serde_json::to_vec(&bad).unwrap()],
            )
            .await;
            reconnect(&runtime, &mut client, &mut task).await;
        }
        assert_eq!(
            send(
                &mut client,
                &[b"PUBLISH", b"jobs", &serde_json::to_vec(&actual).unwrap()]
            )
            .await,
            b":1\r\n"
        );
        send_unmatched(
            &mut client,
            &[b"PUBLISH", b"jobs", &serde_json::to_vec(&actual).unwrap()],
        )
        .await;
        reconnect(&runtime, &mut client, &mut task).await;
        send_unmatched(
            &mut client,
            &[
                b"PUBLISH",
                b"jobs",
                &serde_json::to_vec(&payload(TARGET, "user:8")).unwrap(),
            ],
        )
        .await;
        reconnect(&runtime, &mut client, &mut task).await;
        send_unmatched(
            &mut client,
            &[
                b"PUBLISH",
                b"jobs",
                &serde_json::to_vec(&payload(&Uuid::new_v4().simple().to_string(), "user:7"))
                    .unwrap(),
            ],
        )
        .await;
        reconnect(&runtime, &mut client, &mut task).await;
        assert_eq!(
            send(
                &mut client,
                &[
                    b"PUBLISH",
                    b"jobs",
                    &serde_json::to_vec(&payload(TARGET, "user:7")).unwrap()
                ]
            )
            .await,
            b":1\r\n"
        );
        assert!(
            runtime
                .state
                .lock()
                .await
                .redis
                .snapshot()
                .unused_case
                .is_empty()
        );
        task.abort();
    }
}
