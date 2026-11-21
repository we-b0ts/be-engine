use super::*;

fn stamp(index: usize, lane: u128, sequence: u64, start: Option<i64>, end: Option<i64>) -> Stamp {
    Stamp {
        index,
        connection: Some(Uuid::from_u128(lane)),
        sequence: Some(sequence),
        start: start.map(|value| DateTime::from_timestamp(value, 0).unwrap()),
        end: end.map(|value| DateTime::from_timestamp(value, 0).unwrap()),
    }
}

fn timed(index: usize, lane: u128, sequence: u64, start: i64, end: i64) -> Stamp {
    stamp(index, lane, sequence, Some(start), Some(end))
}

fn point() -> (Endpoint, Location) {
    (
        Endpoint {
            host: "redis".into(),
            port: 6379,
        },
        Location::String(0, bytes::Bytes::from_static(b"key")),
    )
}

#[test]
fn earlier_overlap_does_not_poison_a_later_write() {
    let (endpoint, location) = point();
    let mut case = ScopeHistory::default();
    let run = ScopeHistory::default();
    case.record(&endpoint, location.clone(), timed(0, 1, 1, 0, 4), None);
    case.record(&endpoint, location.clone(), timed(1, 2, 1, 1, 5), None);
    case.record(&endpoint, location.clone(), timed(2, 1, 2, 6, 7), Some(1));
    case.prepare();
    let write = case
        .writer(&run, &endpoint, timed(3, 1, 3, 8, 9), &location)
        .unwrap();
    assert_eq!((write.stamp.index, write.argument), (2, Some(1)));
}

#[test]
fn future_overlap_does_not_poison_an_earlier_read() {
    let (endpoint, location) = point();
    let mut case = ScopeHistory::default();
    let run = ScopeHistory::default();
    case.record(&endpoint, location.clone(), timed(0, 1, 1, 0, 1), Some(1));
    case.record(&endpoint, location.clone(), timed(1, 2, 1, 4, 7), Some(1));
    case.record(&endpoint, location.clone(), timed(2, 3, 1, 5, 8), Some(1));
    case.prepare();
    let write = case
        .writer(&run, &endpoint, timed(3, 1, 2, 2, 3), &location)
        .unwrap();
    assert_eq!(write.stamp.index, 0);
    assert!(
        case.writer(&run, &endpoint, timed(4, 4, 1, 6, 9), &location)
            .is_none()
    );
    assert!(
        case.writer(&run, &endpoint, timed(5, 4, 2, 9, 10), &location)
            .is_none()
    );
}

#[test]
fn proven_write_can_supersede_earlier_overlapping_ancestor_boundaries() {
    let (endpoint, location) = point();
    let mut run = ScopeHistory::default();
    let mut case = ScopeHistory::default();
    run.record(&endpoint, Location::Database(0), timed(0, 1, 1, 0, 4), None);
    run.record(&endpoint, Location::Database(0), timed(1, 2, 1, 1, 5), None);
    case.record(&endpoint, location.clone(), timed(2, 3, 1, 6, 7), Some(1));
    let write = case
        .writer(&run, &endpoint, timed(3, 3, 2, 8, 9), &location)
        .unwrap();
    assert_eq!(write.stamp.index, 2);
}

#[test]
fn known_wall_boundary_implies_predecessors_with_missing_clocks() {
    let (endpoint, location) = point();
    let mut case = ScopeHistory::default();
    let run = ScopeHistory::default();
    case.record(
        &endpoint,
        location.clone(),
        stamp(0, 1, 1, None, None),
        None,
    );
    case.record(&endpoint, location.clone(), timed(1, 1, 2, 6, 7), Some(1));
    case.record(&endpoint, location.clone(), timed(2, 1, 3, 10, 11), Some(1));
    let write = case
        .writer(&run, &endpoint, timed(3, 2, 1, 8, 9), &location)
        .unwrap();
    assert_eq!(write.stamp.index, 1);
}
