use super::*;

fn event(sequence: u64, dependency_sequence: u64, kind: EventKind) -> SourceEvent {
    SourceEvent {
        sequence,
        dependency_sequence,
        offset_micros: sequence * 1_000,
        kind,
    }
}

#[tokio::test]
async fn frontier_wait_retains_notifications_at_the_anchor_and_on_abort() {
    let runtime = SequenceRuntime::with_session_timing(
        SequencePlan::compile([
            event(10, 0, EventKind::SessionSourceStart),
            event(20, 0, EventKind::SessionReady),
            event(40, 0, EventKind::SessionSourceExit),
        ])
        .unwrap(),
        Some(std::time::Duration::ZERO),
        [40],
    );

    let passed = runtime.wait_for_frontier(19).unwrap();
    let at_ready = runtime.wait_for_frontier(20).unwrap();
    let cancelled = runtime.wait_for_frontier(40).unwrap();
    let at_exit = runtime.wait_for_frontier(40).unwrap().changed();
    tokio::pin!(at_exit);
    drop(cancelled);

    runtime.commit_driver(10).unwrap();
    assert!(futures_util::poll!(std::pin::pin!(passed.changed())).is_ready());
    assert!(futures_util::poll!(std::pin::pin!(at_ready.changed())).is_ready());
    assert!(runtime.wait_for_frontier(19).is_none());
    assert!(runtime.wait_for_frontier(20).is_none());
    assert!(futures_util::poll!(at_exit.as_mut()).is_pending());

    runtime.abort();
    assert!(futures_util::poll!(at_exit.as_mut()).is_ready());
    assert!(runtime.wait_for_frontier(40).is_none());
}

#[tokio::test]
async fn message_watch_only_signals_the_message_frontier_and_abort() {
    let runtime = SequenceRuntime::with_session_timing(
        SequencePlan::compile([
            event(1, 0, EventKind::SessionSourceStart),
            event(2, 2, EventKind::Request),
            event(3, 2, EventKind::ResponseEnd),
            event(4, 4, EventKind::Message),
            event(5, 4, EventKind::ResponseEnd),
        ])
        .unwrap(),
        Some(std::time::Duration::ZERO),
        [],
    );
    let mut messages = runtime.subscribe_messages();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    runtime.commit_driver(1).unwrap();
    let request = runtime.admit(2).unwrap();
    request.wait_delivery(deadline).await.unwrap();
    assert!(!messages.has_changed().unwrap());

    request.publish().unwrap();
    assert!(messages.has_changed().unwrap());
    messages.borrow_and_update();

    let push = runtime.admit(4).unwrap();
    push.wait_delivery(deadline).await.unwrap();
    push.publish().unwrap();
    assert!(!messages.has_changed().unwrap());
    runtime.abort();
    assert!(messages.has_changed().unwrap());
}

#[tokio::test]
async fn output_start_allows_a_causally_subsequent_request_before_its_flush_receipt() {
    let runtime = SequenceRuntime::new(
        SequencePlan::compile([
            event(1, 1, EventKind::Request),
            event(2, 1, EventKind::ResponseEndStarted),
            event(3, 2, EventKind::Request),
            event(4, 1, EventKind::ResponseEnd),
            event(5, 2, EventKind::ResponseEndStarted),
            event(6, 2, EventKind::ResponseEnd),
        ])
        .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let first = runtime.admit(1).unwrap();
    first.wait_delivery(deadline).await.unwrap();
    assert_eq!(runtime.expected().unwrap().dependency_sequence, 2);
    first.publish().unwrap();
    assert!(!first.complete());
    let second = runtime.admit(2).unwrap();
    assert!(first.complete());
    second.wait_delivery(deadline).await.unwrap();
    second.publish().unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn a_waiting_output_wakes_on_progress_and_can_be_invalidated_after_reserving() {
    let runtime = SequenceRuntime::new(
        SequencePlan::compile([
            event(1, 1, EventKind::Request),
            event(2, 2, EventKind::Request),
            event(3, 1, EventKind::ResponseEndStarted),
            event(4, 2, EventKind::ResponseEndStarted),
            event(5, 1, EventKind::ResponseEnd),
            event(6, 2, EventKind::ResponseEnd),
        ])
        .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let first = runtime.admit(1).unwrap();
    let second = runtime.admit(2).unwrap();
    let (registered, registration) = tokio::sync::oneshot::channel();
    let waiter = tokio::spawn({
        let second = second.clone();
        async move {
            let delivery = second.wait_delivery(deadline);
            tokio::pin!(delivery);
            assert!(futures_util::poll!(delivery.as_mut()).is_pending());
            registered.send(()).unwrap();
            delivery.await.unwrap();
        }
    });
    registration.await.unwrap();

    first.wait_delivery(deadline).await.unwrap();
    waiter.await.unwrap();
    assert!(!second.sequence_failed());
    first.fail();
    assert!(second.sequence_failed());
}

#[tokio::test]
async fn a_flushed_terminal_receipt_survives_its_claim_while_an_earlier_push_finishes() {
    let runtime = SequenceRuntime::with_session_timing(
        SequencePlan::compile([
            event(7743, 7743, EventKind::Request),
            event(7762, 7762, EventKind::Message),
            event(7763, 7743, EventKind::ResponseHeadersStarted),
            event(7764, 7762, EventKind::ResponseEndStarted),
            event(7765, 7743, EventKind::ResponseEndStarted),
            event(7766, 7762, EventKind::ResponseEnd),
            event(7767, 7743, EventKind::ResponseHeaders),
            event(7768, 7743, EventKind::ResponseEnd),
        ])
        .unwrap(),
        Some(std::time::Duration::ZERO),
        [],
    );
    let response = runtime.admit(7743).unwrap();
    let push = runtime.admit(7762).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);

    response.wait_delivery(deadline).await.unwrap();
    response.publish().unwrap();
    push.wait_delivery(deadline).await.unwrap();
    response.wait_delivery(deadline).await.unwrap();
    response.publish().unwrap();
    assert!(!response.complete());
    assert_eq!(runtime.progress().last_sequence, Some(7765));
    drop(response);

    assert!(!runtime.failed());
    push.publish().unwrap();
    assert_eq!(runtime.progress().last_sequence, Some(7768));
    assert!(runtime.complete());
}

#[tokio::test]
async fn session_driver_and_dependency_receipts_share_the_contiguous_frontier() {
    let runtime = SequenceRuntime::with_session_timing(
        SequencePlan::compile([
            event(1, 0, EventKind::SessionSourceStart),
            event(2, 2, EventKind::Request),
            event(3, 2, EventKind::ResponseEndStarted),
            event(4, 0, EventKind::SessionReady),
            event(5, 2, EventKind::ResponseEnd),
            event(6, 0, EventKind::PrimaryRequest),
            event(7, 0, EventKind::PrimaryResponseEnd),
        ])
        .unwrap(),
        Some(std::time::Duration::ZERO),
        [],
    );
    let primary_request = runtime.wait_for_frontier(6).unwrap().changed();
    tokio::pin!(primary_request);
    assert!(runtime.admit(2).is_err());
    runtime.commit_driver(1).unwrap();
    let claim = runtime.admit(2).unwrap();
    claim
        .wait_delivery(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .unwrap();
    claim.publish().unwrap();
    assert_eq!(runtime.progress().last_sequence, Some(3));
    assert!(futures_util::poll!(primary_request.as_mut()).is_pending());
    assert!(runtime.commit_driver(5).is_err());
    assert!(runtime.commit_driver(6).is_err());
    runtime.commit_driver(4).unwrap();
    assert_eq!(runtime.progress().last_sequence, Some(5));
    assert!(futures_util::poll!(primary_request.as_mut()).is_ready());
    assert!(runtime.driver_due(6).is_none());
    runtime.commit_driver(6).unwrap();
    assert!(!runtime.complete());
    runtime.commit_driver(7).unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn headers_and_body_started_before_one_source_flush_keep_separate_receipts() {
    let runtime = SequenceRuntime::new(
        SequencePlan::compile([
            event(1, 1, EventKind::Request),
            event(2, 1, EventKind::ResponseHeadersStarted),
            event(3, 1, EventKind::ResponsePartStarted),
            event(4, 1, EventKind::ResponseHeaders),
            event(5, 1, EventKind::ResponsePart),
            event(6, 1, EventKind::ResponseEndStarted),
            event(7, 1, EventKind::ResponseEnd),
        ])
        .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    let claim = runtime.admit(1).unwrap();
    claim.wait_delivery(deadline).await.unwrap();
    claim.publish().unwrap();
    claim.wait_body_delivery(deadline).await.unwrap();
    assert_eq!(claim.consecutive_parts(8), 1);
    claim.publish().unwrap();
    claim.wait_body_delivery(deadline).await.unwrap();
    claim.publish().unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn batched_parts_stop_at_the_next_independent_event() {
    let runtime = SequenceRuntime::new(
        SequencePlan::compile([
            event(1, 1, EventKind::Request),
            event(2, 1, EventKind::ResponsePart),
            event(3, 1, EventKind::ResponsePart),
            event(4, 2, EventKind::Request),
            event(5, 1, EventKind::ResponseEnd),
            event(6, 2, EventKind::ResponseEnd),
        ])
        .unwrap(),
    );
    let first = runtime.admit(1).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    first.wait_delivery(deadline).await.unwrap();
    assert_eq!(first.consecutive_parts(100_000), 2);
    assert!(first.publish_parts(3).is_err());
    assert_eq!(runtime.expected().unwrap().sequence, 2);
    first.publish_parts(2).unwrap();
    assert_eq!(runtime.expected().unwrap().sequence, 4);
    let second = runtime.admit(2).unwrap();
    first.wait_delivery(deadline).await.unwrap();
    first.publish().unwrap();
    second.wait_delivery(deadline).await.unwrap();
    second.publish().unwrap();
    assert!(runtime.complete());
}

fn overlap() -> SequenceScheduler {
    SequenceScheduler::new(
        SequencePlan::compile([
            event(1, 10, EventKind::Request),
            event(2, 20, EventKind::Request),
            event(3, 10, EventKind::ResponseEnd),
            event(4, 20, EventKind::ResponseEnd),
        ])
        .unwrap(),
    )
}

#[test]
fn early_request_waits_and_overlap_blocks_the_first_response_until_both_requests_arrive() {
    let mut schedule = overlap();
    assert!(matches!(schedule.admit(20).unwrap(), Admission::Waiting(_)));
    assert_eq!(schedule.admit(10).unwrap(), Admission::Accepted);
    assert!(schedule.reserve_delivery(10).unwrap().is_none());
    assert_eq!(schedule.admit(20).unwrap(), Admission::Accepted);
    assert!(schedule.admit(20).is_err());
    assert!(schedule.admit(999).is_err());
    assert!(schedule.reserve_delivery(20).unwrap().is_none());
    let first = schedule.reserve_delivery(10).unwrap().unwrap();
    assert!(!schedule.consumed(10));
    schedule.finish_delivery(first, true).unwrap();
    assert!(schedule.consumed(10));
    assert!(schedule.finish_delivery(first, true).is_err());
    let second = schedule.reserve_delivery(20).unwrap().unwrap();
    schedule.finish_delivery(second, true).unwrap();
    assert!(schedule.complete());
}

#[test]
fn failed_wire_delivery_cannot_advance_or_manufacture_consumption() {
    let mut schedule = overlap();
    schedule.admit(10).unwrap();
    schedule.admit(20).unwrap();
    let ticket = schedule.reserve_delivery(10).unwrap().unwrap();
    assert!(schedule.finish_delivery(ticket, false).is_err());
    assert!(!schedule.consumed(10));
    assert!(!schedule.complete());
    assert!(schedule.reserve_delivery(20).is_err());
}

#[test]
fn missing_request_diagnosis_is_once_per_event_and_ownership_revision() {
    let mut schedule = overlap();
    assert_eq!(schedule.missing_request(1).unwrap().dependency_sequence, 10);
    assert!(schedule.missing_request(1).is_none());
    assert!(schedule.missing_request(2).is_some());
    schedule.admit(10).unwrap();
    assert_eq!(schedule.missing_request(2).unwrap().dependency_sequence, 20);
}

#[test]
fn response_parts_and_real_termination_keep_the_slot_live_until_the_last_receipt() {
    let mut schedule = SequenceScheduler::new(
        SequencePlan::compile([
            event(1, 1, EventKind::Request),
            event(2, 1, EventKind::ResponsePart),
            event(4, 1, EventKind::ClientTermination),
        ])
        .unwrap(),
    );
    schedule.admit(1).unwrap();
    let part = schedule.reserve_delivery(1).unwrap().unwrap();
    schedule.finish_delivery(part, true).unwrap();
    assert!(!schedule.consumed(1));
    let termination = schedule.reserve_delivery(1).unwrap().unwrap();
    schedule.finish_delivery(termination, true).unwrap();
    assert!(schedule.consumed(1));
}

#[test]
fn invalid_source_order_duplicate_requests_and_incomplete_calls_reject_during_preparation() {
    for events in [
        vec![event(1, 1, EventKind::ResponseEnd)],
        vec![event(1, 1, EventKind::Request)],
        vec![
            event(1, 1, EventKind::Request),
            event(1, 1, EventKind::ResponseEnd),
        ],
        vec![
            event(1, 1, EventKind::Request),
            event(2, 1, EventKind::Request),
        ],
        vec![
            event(1, 1, EventKind::Request),
            event(2, 1, EventKind::ResponseEnd),
            event(3, 1, EventKind::ResponsePart),
        ],
    ] {
        assert!(SequencePlan::compile(events).is_err());
    }
}

#[test]
fn large_recordings_advance_a_prepared_cursor_without_candidate_scans_or_payload_copies() {
    let count = 100_000;
    let plan = SequencePlan::compile((1..=count).flat_map(|dependency| {
        [
            event(dependency * 2 - 1, dependency, EventKind::Request),
            event(dependency * 2, dependency, EventKind::ResponseEnd),
        ]
    }))
    .unwrap();
    assert_eq!(plan.event_count(), 200_000);
    let mut schedule = SequenceScheduler::new(plan);
    for dependency in 1..=count {
        assert_eq!(schedule.expected().unwrap().dependency_sequence, dependency);
        assert_eq!(schedule.admit(dependency).unwrap(), Admission::Accepted);
        let receipt = schedule.reserve_delivery(dependency).unwrap().unwrap();
        schedule.finish_delivery(receipt, true).unwrap();
    }
    assert!(schedule.complete());
}

#[test]
fn immutable_catalog_scopes_keep_original_order_and_visit_only_selected_dependency_postings() {
    use traffic_model::recording::CapturePhase;
    use traffic_model::trace::{CaptureEvent, RecordedEvent};
    let events = [(4, 20, false), (1, 10, true), (3, 10, false), (2, 20, true)].map(
        |(sequence, dependency_sequence, begin)| {
            let event = if begin {
                CaptureEvent::Started {
                    dependency_sequence,
                    phase: CapturePhase::Runtime,
                    observed_case: None,
                    admitted_case: None,
                }
            } else {
                CaptureEvent::Terminal {
                    dependency_sequence,
                    outcome: "response".into(),
                    capture_complete: true,
                }
            };
            RecordedEvent {
                sequence,
                offset_micros: sequence,
                event,
            }
        },
    );
    let catalog = SequenceCatalog::prepare(events).unwrap();
    let plan = catalog.scope([20, 20]).unwrap();
    assert_eq!(plan.dependency_count(), 1);
    assert_eq!(plan.event_count(), 2);
    let schedule = SequenceScheduler::new(plan);
    assert_eq!(schedule.expected().unwrap().sequence, 2);
    assert!(catalog.scope([30]).is_err());
}
