use super::source::sessions as source_sessions;
use super::*;
use crate::interaction::{
    model::{InputAction, InputActionKind, InputTranscript, Protocol, WireMessage},
    policy::InteractionPolicy,
};
use serde_json::json;

fn fixture() -> (InputTranscript, Value) {
    let mut input = InputTranscript::new(Protocol::SocketIo, InteractionPolicy::default());
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: 0,
        offset_us: None,
        after: vec![],
        compressible_gap: false,
        gap_start_ms: None,
        ack_ref: None,
        action: InputActionKind::Message {
            message: WireMessage::text("40/chat,{}"),
        },
    });
    (
        input,
        json!({"interaction":{"version":1,"protocol":"socket_io","events":[
            {"sequence":1,"message":WireMessage::text("40/chat,{\"sid\":\"source-sid\"}")},
            {"sequence":2,"message":WireMessage::text("42/chat,[\"private-business\",{\"sid\":\"not-a-connection\"}]")}
        ]}}),
    )
}

#[test]
fn only_a_unique_source_connect_matching_an_original_input_supplies_an_identity() {
    let (input, mut output) = fixture();
    assert_eq!(
        source_sessions(&input, &output),
        BTreeMap::from([("/chat".into(), "source-sid".into())])
    );
    let original = output["interaction"]["events"][0].clone();
    output["interaction"]["events"]
        .as_array_mut()
        .unwrap()
        .push(original);
    assert!(
        source_sessions(&input, &output).is_empty(),
        "duplicate Source connections are ambiguous"
    );
    output["interaction"]["events"][0]["message"]["data"] = "40/chat,{}".into();
    assert!(
        source_sessions(&input, &output).is_empty(),
        "a CONNECT without a SID still makes multiple connections ambiguous"
    );
    let (mut input, output) = fixture();
    input.actions.push(input.actions[0].clone());
    assert!(
        source_sessions(&input, &output).is_empty(),
        "reconnections need a separate native lifetime proof"
    );
    let (_, mut output) = fixture();
    output["interaction"]["events"][0]["message"]["data"] =
        "40/other,{\"sid\":\"source-sid\"}".into();
    assert!(source_sessions(&fixture().0, &output).is_empty());
}

#[test]
fn protected_source_namespace_metadata_is_authenticated_without_changing_recordings() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join(".traffic-e2e/local")).unwrap();
    crate::platform::encryption_key::load_or_create(project.path()).unwrap();
    let directory = project.path().join(".traffic-e2e/local/artifacts/case");
    std::fs::create_dir_all(&directory).unwrap();
    let request_path = directory.join("request.json");
    let output_path = directory.join("expected-response.json");
    let (input, mut output) = fixture();
    let mut request = json!({"method":"GET","uri":"/socket.io/","headers":{},"interaction":input});
    crate::interaction::private::protect_request(&mut request, &request_path).unwrap();
    crate::interaction::private::protect_output(&mut output, &output_path).unwrap();
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let output_bytes = serde_json::to_vec(&output).unwrap();
    assert!(!String::from_utf8_lossy(&output_bytes).contains("source-sid"));
    std::fs::write(&request_path, &request_bytes).unwrap();
    std::fs::write(&output_path, &output_bytes).unwrap();
    let cases = BTreeMap::from([(
        "case".into(),
        ReplayCase {
            id: "case".into(),
            dir: directory.clone(),
            dependencies_path: directory.join("dependencies.jsonl"),
            status: crate::replay::ReplayCaseStatus::Pending,
        },
    )]);
    let mut sessions = NamespaceSessions::default();
    sessions.prepare(&cases).unwrap();
    assert_eq!(sessions.source["case"].sids["/chat"], "source-sid");
    assert_eq!(std::fs::read(&request_path).unwrap(), request_bytes);
    assert_eq!(std::fs::read(&output_path).unwrap(), output_bytes);
    let encrypted = output["interaction"]["events"][0]["message"]["data"]
        .as_str()
        .unwrap();
    let (prefix, data) = encrypted.rsplit_once(':').unwrap();
    let mut data = data.as_bytes().to_vec();
    data[0] = if data[0] == b'A' { b'B' } else { b'A' };
    output["interaction"]["events"][0]["message"]["data"] =
        format!("{prefix}:{}", String::from_utf8(data).unwrap()).into();
    std::fs::write(&output_path, output.to_string()).unwrap();
    assert!(
        NamespaceSessions::default().prepare(&cases).is_err(),
        "tampered Source output cannot establish protocol identity"
    );
}

#[test]
fn room_mapping_requires_live_observation_and_cannot_escape_case_namespace_or_epoch() {
    let (input, output) = fixture();
    let mut sessions = NamespaceSessions::default();
    sessions.source.insert(
        "case".into(),
        Source {
            sids: source_sessions(&input, &output),
            window: None,
        },
    );
    let epoch = Utc::now();
    let matches = |sessions: &NamespaceSessions, case, namespace, target| {
        sessions.matches_sid(
            Some(case),
            &json!(namespace),
            &json!("source-sid"),
            &json!(target),
        )
    };
    assert!(!matches(&sessions, "case", "/chat", "target-sid"));
    assert!(
        sessions
            .connected("case", epoch, "/chat", Some("target-sid"))
            .is_err()
    );
    sessions.request_begin("case", epoch).unwrap();
    assert!(
        sessions
            .connected("case", epoch, "/chat", Some("target-sid"))
            .is_err()
    );
    sessions.observe_begin("case", epoch).unwrap();
    assert!(
        sessions
            .connected(
                "case",
                epoch - chrono::TimeDelta::milliseconds(1),
                "/chat",
                Some("target-sid")
            )
            .is_err()
    );
    sessions.connected("case", epoch, "/chat", None).unwrap();
    assert!(!matches(&sessions, "case", "/chat", "target-sid"));
    sessions
        .connected("case", epoch, "/chat", Some("target-sid"))
        .unwrap();
    assert!(matches(&sessions, "case", "/chat", "target-sid"));
    assert!(!matches(&sessions, "other", "/chat", "target-sid"));
    assert!(!matches(&sessions, "case", "/other", "target-sid"));
    assert!(!matches(&sessions, "case", "/chat", "wrong-sid"));
    assert!(!sessions.matches_sid(
        Some("case"),
        &json!("/chat"),
        &json!("user:7"),
        &json!("target-sid")
    ));
    assert!(
        sessions
            .connected("case", epoch, "/chat", Some("changed-sid"))
            .is_err()
    );
    sessions.close_case("case");
    assert!(!matches(&sessions, "case", "/chat", "target-sid"));
    assert!(
        sessions
            .connected("case", epoch, "/chat", Some("target-sid"))
            .is_err()
    );
    sessions.begin_case();
    sessions
        .request_begin("case", epoch + chrono::TimeDelta::seconds(1))
        .unwrap();
    assert!(!matches(&sessions, "case", "/chat", "target-sid"));
}
