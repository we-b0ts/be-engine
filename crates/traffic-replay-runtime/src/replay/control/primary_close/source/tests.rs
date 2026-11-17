use super::*;

fn epoch() -> DateTime<Utc> {
    "2026-11-03T13:28:26Z".parse().unwrap()
}

fn stream() -> SourceStream {
    SourceStream {
        reference: reference(),
        started_at: epoch(),
        headers_ms: 10,
        chunks_ms: vec![90_000, 99_000, 101_000],
        end_ms: 142_000,
    }
}

fn reference() -> ProtocolExchange {
    ProtocolExchange {
        inventory: traffic_protocol::ProtocolId::new("custom"),
        index: 7,
    }
}

#[test]
fn one_mapping_keeps_close_between_earlier_and_later_dependency_data() {
    for cap in [0, 5, 50] {
        let plan = build(epoch(), 100_000, vec![stream()], cap).unwrap();
        let s = &plan.streams[&reference()];
        assert_eq!(s.prefix_chunks, 2);
        assert!(s.chunks_ms[1] <= plan.close_ms && plan.close_ms <= s.chunks_ms[2]);
        assert!(s.end_after_close && s.prefix_required && !s.headers_after_close);
        assert!(s.end_ms <= cap * 6);
    }
}

#[test]
fn equal_native_indexes_keep_independent_delivery_barriers() {
    let first = stream();
    let mut second = stream();
    second.reference.inventory = traffic_protocol::ProtocolId::new("another_custom");
    let first_reference = first.reference;
    let second_reference = second.reference;
    let plan = build(epoch(), 100_000, vec![first, second], 0).unwrap();
    let timeline = Arc::new(Timeline {
        case: "case".into(),
        epoch: epoch(),
        admission_epoch: 0,
        started: MonoInstant::now(),
        plan,
        prefixes: SyncMutex::default(),
        primary_close: SyncMutex::new(None),
        stage: watch::channel(0).0,
    });
    let first_progress = DeliveryProgress::default();
    let second_progress = DeliveryProgress::default();
    let first = timeline
        .bind(first_reference, first_progress.clone())
        .unwrap()
        .unwrap();
    let second = timeline
        .bind(second_reference, second_progress.clone())
        .unwrap()
        .unwrap();
    first.prefix.queued();
    second.prefix.queued();
    first_progress.flushed();
    assert!(!timeline.ready());
    second_progress.flushed();
    assert!(timeline.ready());
    assert!(
        timeline
            .bind(first_reference, DeliveryProgress::default())
            .is_err()
    );
    assert!(timeline.ready());
}

#[test]
fn late_target_request_does_not_change_the_source_cutoff_or_clock_mapping() {
    let plan = build(epoch(), 100_000, vec![stream()], 5).unwrap();
    assert_eq!(plan.streams[&reference()].prefix_chunks, 2);
    assert_eq!(plan.close_ms, 20);
    // Actual late admission waits for its wire prefix, not a shifted cutoff.
    let timeline = Timeline {
        primary_close: SyncMutex::new(None),
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
fn invalid_dependency_clocks_cannot_authorize_timeline_compression() {
    let mut s = stream();
    s.started_at = epoch() - chrono::TimeDelta::seconds(1);
    assert!(build(epoch(), 100_000, vec![s], 5).is_err());
    let mut s = stream();
    s.chunks_ms[1] = 80_000;
    assert!(build(epoch(), 100_000, vec![s], 5).is_err());
}

#[test]
fn fractional_request_clock_cannot_pull_a_post_close_chunk_before_the_cutoff() {
    let mut source = stream();
    source.started_at += chrono::TimeDelta::microseconds(400);
    source.chunks_ms[0] = 99_999;
    source.chunks_ms[1] = 100_000;
    let plan = build(epoch(), 100_000, vec![source], 5).unwrap();
    assert_eq!(plan.streams[&reference()].prefix_chunks, 1);
}
