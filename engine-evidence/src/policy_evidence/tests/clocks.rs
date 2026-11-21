//! Signed clocks retain independent request and delivered-input provenance.
use super::*;

fn at(seconds: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(seconds, 0)
}

#[test]
fn sealed_request_observations_keep_their_own_start_and_reject_clock_substitution() {
    let (_temp, artifacts, store, mut metadata) = setup();
    metadata.clocks = WitnessClocks {
        case: ClockPair {
            source: at(1000),
            target: at(2000),
        },
        dependency: ClockPair {
            source: at(1030),
            target: at(2040),
        },
        ..Default::default()
    };
    let mut witnesses = vec![];
    for (id, started) in [("first", 2040), ("second", 2070)] {
        metadata.clocks.dependency.target = at(started);
        witnesses.push(
            store
                .record_observation(
                    metadata.clone(),
                    &artifacts,
                    b"source",
                    Some(b"target"),
                    Some(id),
                )
                .unwrap()
                .unwrap(),
        );
    }
    let manifest = store.sealed_manifest().unwrap();
    let private = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    for (witness, started) in witnesses.iter().zip([2040, 2070]) {
        assert_eq!(
            read(&private, witness, &artifacts).unwrap().1,
            Some(b"target".to_vec())
        );
        let comparison = witness.metadata.clocks.comparison();
        assert_eq!(comparison.observation().source, at(1030));
        assert_eq!(comparison.observation().target, at(started));
        assert_eq!(comparison.case.target, at(2000));
        let mut forged = witness.clone();
        forged.metadata.clocks.dependency.target = at(2000);
        assert!(read(&private, &forged, &artifacts).is_err());
    }
    let mut missing = metadata.clocks;
    missing.dependency = ClockPair::default();
    assert!(missing.comparison().observation().source.is_none());
    assert!(missing.comparison().observation().target.is_none());
}

#[test]
fn sealed_delivered_input_retains_request_and_delivery_clocks_as_distinct_facts() {
    let (_temp, artifacts, store, mut metadata) = setup();
    metadata.surface = Surface::DependencyResponse;
    metadata.source_role = SourceRole::DependencyResponse;
    metadata.target_role = TargetRole::DeliveredInput;
    metadata.clocks = WitnessClocks {
        case: ClockPair {
            source: at(1000),
            target: at(2000),
        },
        dependency: ClockPair {
            source: at(1030),
            target: at(2040),
        },
        delivery: ClockPair {
            source: at(1060),
            target: at(2080),
        },
    };
    let witness = store
        .record_observation(
            metadata.clone(),
            &artifacts,
            b"original-read",
            Some(b"delivered-input"),
            Some("read"),
        )
        .unwrap()
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    let private = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    assert_eq!(
        read(&private, &witness, &artifacts).unwrap().1,
        Some(b"delivered-input".to_vec())
    );
    assert_eq!(witness.metadata.clocks, metadata.clocks);
    assert_eq!(
        witness.metadata.clocks.comparison().delivery.target,
        at(2080)
    );
    let mut forged = witness.clone();
    forged.metadata.clocks.delivery.target = metadata.clocks.dependency.target;
    assert!(read(&private, &forged, &artifacts).is_err());
    let mut forged = witness;
    forged.metadata.target_role = TargetRole::IndependentTargetObservation;
    assert!(read(&private, &forged, &artifacts).is_err());
}
