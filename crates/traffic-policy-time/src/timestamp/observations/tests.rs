use super::*;
use traffic_policy::{Observations, PolicyProvider};

fn one(scope: ScopeKey, pair: (i128, i128)) -> TimestampObservations {
    TimestampObservations::one("dependency".into(), Some("response".into()), scope, pair)
}

#[test]
fn repeated_frames_deduplicate_and_validate_relationships() {
    let mut state = one(ScopeKey::Shared, (1, 61));
    for _ in 0..1000 {
        state.merge(&one(ScopeKey::Shared, (1, 61))).unwrap();
    }
    assert_eq!(state.groups.values().next().unwrap().len(), 1);
    assert!(state.merge(&one(ScopeKey::Shared, (1, 62))).is_err());
}

#[test]
fn all_non_shared_scopes_use_one_bounded_relationship_budget() {
    let mut state = TimestampObservations::default();
    for index in 0..MAX_OBSERVATIONS {
        state
            .merge(&one(
                ScopeKey::ArrayElement(format!("/blocks/{index}")),
                (1, 101),
            ))
            .unwrap();
    }
    assert!(
        state
            .merge(&one(ScopeKey::Entity([0; 32]), (1, 101)))
            .is_err()
    );
    state
        .merge(&one(ScopeKey::ArrayElement("/blocks/0".into()), (1, 101)))
        .unwrap();
    assert_eq!(state.groups.len(), MAX_OBSERVATIONS);
}

#[test]
fn failed_observation_merge_keeps_previous_state() {
    let descriptor = crate::TimestampPolicy.descriptor();
    let mut state = Observations::default();
    state
        .observe(&descriptor, Box::new(one(ScopeKey::Shared, (1, 61))))
        .unwrap();
    let mut other = one(ScopeKey::ArrayElement("/block/0".into()), (1, 61));
    other.merge(&one(ScopeKey::Shared, (1, 62))).unwrap();
    assert!(state.observe(&descriptor, Box::new(other)).is_err());
    // This relationship would conflict with the rejected incoming array scope.
    state
        .observe(
            &descriptor,
            Box::new(one(ScopeKey::ArrayElement("/block/0".into()), (1, 62))),
        )
        .unwrap();
}
