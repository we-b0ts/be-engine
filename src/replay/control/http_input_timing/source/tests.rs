use super::*;
use crate::http::stream::ResponseChunk;
use crate::interaction::{model::InputAction, policy::InteractionPolicy};

fn epoch() -> DateTime<Utc> {
    "2026-11-03T13:28:26Z".parse().unwrap()
}

fn stream() -> SourceStream {
    SourceStream {
        index: 7,
        started_at: epoch(),
        stream: ResponseStream {
            version: 2,
            headers_ms: 10,
            chunks: vec![
                ResponseChunk {
                    at_ms: 90_000,
                    start: 0,
                    end: 3,
                },
                ResponseChunk {
                    at_ms: 99_000,
                    start: 3,
                    end: 6,
                },
                ResponseChunk {
                    at_ms: 101_000,
                    start: 6,
                    end: 9,
                },
            ],
            end_ms: 142_000,
            complete: true,
            trailers: None,
        },
    }
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
fn one_mapping_keeps_close_between_earlier_and_later_dependency_data() {
    for cap in [0, 5, 50] {
        let plan = build(epoch(), 100_000, vec![stream()], cap).unwrap();
        let s = &plan.streams[&7];
        assert_eq!(s.prefix_chunks, 2);
        assert!(s.chunks_ms[1] <= plan.close_ms && plan.close_ms <= s.chunks_ms[2]);
        assert!(s.end_after_close && s.prefix_required && !s.headers_after_close);
        assert!(s.end_ms <= cap * 6);
    }
}

#[test]
fn late_target_request_does_not_change_the_source_cutoff_or_clock_mapping() {
    let plan = build(epoch(), 100_000, vec![stream()], 5).unwrap();
    assert_eq!(plan.streams[&7].prefix_chunks, 2);
    assert_eq!(plan.close_ms, 20);
    // Actual late admission waits for its wire prefix, not a shifted cutoff.
    let timeline = Timeline {
        case: "case".into(),
        epoch: epoch(),
        admission_epoch: 0,
        started: MonoInstant::now() - Duration::from_secs(1),
        plan,
        prefixes: SyncMutex::default(),
        stage: watch::channel(0).0,
    };
    assert!(
        !timeline.ready(),
        "elapsed wall time cannot replace unstarted delivery"
    );
}

#[test]
fn response_adoption_uses_original_admission_instead_of_late_headers_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    let case = ReplayCase {
        id: "case".into(),
        dir: temp.path().into(),
        dependencies_path: temp.path().join("unused"),
        status: ReplayCaseStatus::Pending,
    };
    std::fs::write(
        case.dir.join("request.json"),
        serde_json::json!({
            "timestamp":epoch()+chrono::TimeDelta::milliseconds(500),"interaction":input()
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        case.dir.join("admission.json"),
        serde_json::json!({
            "timestamp":epoch(),"case_id":"case"
        })
        .to_string(),
    )
    .unwrap();
    let mut s = stream();
    s.stream.chunks[1].at_ms = 100_100;
    let plan = prepare(&case, vec![s], 5).unwrap().unwrap();
    assert_eq!(
        plan.streams[&7].prefix_chunks, 1,
        "late adopted clock must not move post-close bytes before close"
    );
    std::fs::write(
        case.dir.join("admission.json"),
        serde_json::json!({
            "timestamp":epoch(),"case_id":"other-case"
        })
        .to_string(),
    )
    .unwrap();
    assert!(prepare(&case, vec![stream()], 5).is_err());
}

#[test]
fn invalid_dependency_clocks_cannot_authorize_timeline_compression() {
    let mut s = stream();
    s.started_at = epoch() - chrono::TimeDelta::seconds(1);
    assert!(build(epoch(), 100_000, vec![s], 5).is_err());
    let mut s = stream();
    s.stream.chunks[1].at_ms = 80_000;
    assert!(build(epoch(), 100_000, vec![s], 5).is_err());
}
