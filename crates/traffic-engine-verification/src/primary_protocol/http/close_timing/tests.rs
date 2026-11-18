use super::*;
use crate::interaction::{model::InputAction, policy::InteractionPolicy};

fn epoch() -> DateTime<Utc> {
    "2026-11-03T13:28:26Z".parse().unwrap()
}

fn input() -> InputTranscript {
    let mut input = InputTranscript::new(
        Protocol::Sse,
        InteractionPolicy {
            request_timeout_ms: 900_000,
            max_duration_ms: 900_000,
            ..InteractionPolicy::default()
        },
    );
    input.actions.push(InputAction {
        sequence: 1,
        offset_ms: 100_000,
        offset_us: None,
        after: vec![],
        gap_start_ms: None,
        ack_ref: None,
        compressible_gap: false,
        action: InputActionKind::Close {
            code: None,
            reason: String::new(),
        },
    });
    input
}

#[test]
fn response_adoption_uses_original_admission_instead_of_late_headers_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("request.json"),
        serde_json::json!({
            "timestamp":epoch()+chrono::TimeDelta::milliseconds(500),"interaction":input()
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        temp.path().join("admission.json"),
        serde_json::json!({
            "timestamp":epoch(),"case_id":"case"
        })
        .to_string(),
    )
    .unwrap();
    let source = project(temp.path(), "case").unwrap().unwrap();
    assert_eq!(source.epoch, epoch());
    assert_eq!(source.close_ms, 100_000);
    std::fs::write(
        temp.path().join("admission.json"),
        serde_json::json!({
            "timestamp":epoch(),"case_id":"other-case"
        })
        .to_string(),
    )
    .unwrap();
    assert!(project(temp.path(), "case").is_err());
}
