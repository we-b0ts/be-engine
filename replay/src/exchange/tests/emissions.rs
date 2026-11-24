use super::*;
use crate::{EventKind, SequenceBinding, SequencePlan, SequenceRuntime, SourceEvent};
use traffic_protocol::connection::RecordedInput;

fn with_emission() -> ExchangeInventory {
    let mut inventory = inventory(ReplaySource::Case);
    inventory
        .register(
            PROTOCOL,
            RecordedExchange {
                reference: ProtocolRef::exchange(PROTOCOL.as_str(), Uuid::new_v4()),
                endpoint: endpoint(),
                lane: None,
                response_delay: Default::default(),
                input: RecordedInput::Emission {
                    after: inventory.exchanges[0].native.reference.clone(),
                    offset: Default::default(),
                },
                response: Arc::new(Message("notification")),
            },
            SourceContext {
                source: ReplaySource::Case,
                case_id: Some("case".into()),
                position: 2,
                capture: None,
            },
            ExchangeRules::default(),
        )
        .unwrap();
    inventory.seal();
    let events = [
        (1, EventKind::Request),
        (1, EventKind::ResponseEnd),
        (3, EventKind::Message),
        (3, EventKind::ResponseEnd),
        (2, EventKind::Request),
        (2, EventKind::ResponseEnd),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (dependency_sequence, kind))| SourceEvent {
        sequence: index as u64 + 1,
        dependency_sequence,
        offset_micros: index as u64,
        kind,
    });
    let runtime = SequenceRuntime::new(SequencePlan::compile(events).unwrap());
    inventory.lifecycle.sequence =
        SequenceBinding::new(runtime, [(0, 1), (1, 2), (2, 3)].into_iter());
    inventory
}

#[test]
fn exclusive_native_sessions_keep_one_source_lane_until_the_physical_owner_releases_it() {
    let mut inventory = inventory(ReplaySource::Case);
    let first_owner = Uuid::new_v4();
    let other_owner = Uuid::new_v4();
    let _first = inventory.claim_bound(0, first_owner).unwrap();
    let selected = |owner| {
        inventory
            .select(
                MatchContext {
                    protocol: PROTOCOL,
                    endpoint: &endpoint(),
                    active_case: Some("case"),
                    request: &Message("second"),
                    session: owner,
                    lane: None,
                    request_session: None,
                    metadata: &(),
                },
                |_| (),
                |_, _| Ok(()),
            )
            .unwrap()
    };
    assert!(matches!(selected(Some(first_owner)), Selection::Matched(_)));
    assert!(matches!(selected(Some(other_owner)), Selection::NotFound));
    assert!(matches!(selected(None), Selection::NotFound));
    assert!(
        inventory
            .sessions
            .bind(PROTOCOL, &endpoint(), "native-session", other_owner)
            .is_err()
    );
    inventory.sessions.release(first_owner);
    assert!(matches!(selected(Some(other_owner)), Selection::Matched(_)));
}

#[tokio::test]
async fn emission_is_a_distinct_source_obligation_with_scope_and_real_delivery_barriers() {
    let mut inventory = with_emission();
    let anchors = [inventory.exchanges[0].native.reference.clone()];
    assert!(
        inventory
            .select_message(PROTOCOL, &endpoint(), Some("case"), &anchors)
            .is_none()
    );
    let first = inventory.claim(0).unwrap();
    first.wait_sequence_delivery().await.unwrap();
    assert!(
        inventory
            .select_message(PROTOCOL, &endpoint(), Some("case"), &anchors)
            .is_none()
    );
    assert!(first.publish_wire());
    assert!(matches!(
        inventory.finish(0, &first, || Ok(())),
        Finish::Committed(())
    ));
    assert_eq!(
        inventory.select_message(PROTOCOL, &endpoint(), Some("case"), &anchors),
        Some(2)
    );
    assert!(
        inventory
            .select_message(PROTOCOL, &endpoint(), Some("other"), &anchors)
            .is_none()
    );
    assert!(
        inventory
            .select_message(
                ProtocolId::new("other"),
                &endpoint(),
                Some("case"),
                &anchors
            )
            .is_none()
    );
    assert!(
        inventory
            .select_message(
                PROTOCOL,
                &Endpoint {
                    port: 1,
                    ..endpoint()
                },
                Some("case"),
                &anchors
            )
            .is_none()
    );
    assert!(
        inventory
            .select_message(PROTOCOL, &endpoint(), Some("case"), &[])
            .is_none()
    );
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "second"),
        Selection::NotFound
    ));
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "notification"),
        Selection::NotFound
    ));
    let message = inventory.claim(2).unwrap();
    message.wait_sequence_delivery().await.unwrap();
    assert!(matches!(
        inventory.finish(2, &message, || Ok(())),
        Finish::Unchanged
    ));
    assert!(message.publish_wire());
    assert!(matches!(
        inventory.finish(2, &message, || Ok(())),
        Finish::Committed(())
    ));
    assert!(
        inventory
            .select_message(PROTOCOL, &endpoint(), Some("case"), &anchors)
            .is_none()
    );
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "second"),
        Selection::Matched(_)
    ));
}

#[tokio::test]
async fn prepared_trace_selects_requests_and_messages_without_postings() {
    let mut inventory = with_emission();
    inventory.candidates = Default::default();
    inventory.emissions.clear();

    assert!(matches!(
        select(&inventory, ReplaySource::Case, "second"),
        Selection::NotFound
    ));
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "first"),
        Selection::Matched(selected) if selected.index == 0
    ));
    let first = inventory.claim(0).unwrap();
    first.wait_sequence_delivery().await.unwrap();
    assert!(first.publish_wire());
    assert!(matches!(
        inventory.finish(0, &first, || Ok(())),
        Finish::Committed(())
    ));
    let anchor = inventory.exchanges[0].native.reference.clone();
    assert_eq!(
        inventory.select_message(PROTOCOL, &endpoint(), Some("case"), &[anchor]),
        Some(2)
    );
}

#[test]
fn session_emissions_select_the_global_head_without_a_case_candidate_scan() {
    let mut inventory = with_emission();
    let anchor = inventory.exchanges[0].native.reference.clone();
    let index = inventory
        .register(
            PROTOCOL,
            RecordedExchange {
                reference: ProtocolRef::exchange(PROTOCOL.as_str(), Uuid::new_v4()),
                endpoint: endpoint(),
                lane: None,
                response_delay: Default::default(),
                input: RecordedInput::Emission {
                    after: anchor.clone(),
                    offset: Default::default(),
                },
                response: Arc::new(Message("session notification")),
            },
            SourceContext {
                source: ReplaySource::Startup,
                case_id: None,
                position: 3,
                capture: None,
            },
            ExchangeRules::default(),
        )
        .unwrap();
    inventory.seal();
    let plan = SequencePlan::compile(
        [EventKind::Message, EventKind::ResponseEnd]
            .into_iter()
            .enumerate()
            .map(|(position, kind)| SourceEvent {
                sequence: position as u64 + 1,
                dependency_sequence: 4,
                offset_micros: 0,
                kind,
            }),
    )
    .unwrap();
    let runtime = SequenceRuntime::with_session_timing(plan, Some(std::time::Duration::ZERO), []);
    inventory.lifecycle.sequence = SequenceBinding::default();
    inventory
        .lifecycle
        .sequence
        .attach_run(SequenceBinding::new(runtime, [(index, 4)].into_iter()));

    assert_eq!(
        inventory.select_message(PROTOCOL, &endpoint(), Some("case"), &[anchor]),
        Some(index)
    );
}

#[tokio::test]
async fn cancelled_emission_remains_failed_and_cannot_advance_to_the_next_request() {
    let mut inventory = with_emission();
    let first = inventory.claim(0).unwrap();
    first.wait_sequence_delivery().await.unwrap();
    assert!(first.publish_wire());
    inventory.finish(0, &first, || Ok(()));
    let message = inventory.claim(2).unwrap();
    message.wait_sequence_delivery().await.unwrap();
    drop(message);
    assert_eq!(
        inventory
            .lifecycle
            .live_status(2, inventory.exchanges[2].status),
        ReplayExchangeStatus::Failed
    );
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "second"),
        Selection::NotFound
    ));
}
