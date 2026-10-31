//! Observation volume cannot grow retained metadata beyond Source proof keys.
use super::*;

fn event(namespace: &str, name: &str, ordinal: u64) -> NativeEvent {
    NativeEvent {
        namespace: namespace.into(),
        event: name.into(),
        ordinal,
    }
}

#[test]
fn high_volume_observations_keep_bounded_metadata_and_reject_new_namespaces() {
    let epoch = Utc::now();
    let mut ingress = Ingress::default();
    assert!(ingress.observe_begin("case", epoch, true));
    for ordinal in 1..=12_553 {
        ingress
            .observe(
                "case",
                epoch,
                &event("/chat", &format!("actual:{ordinal}"), ordinal),
            )
            .unwrap();
    }
    let live = ingress.observed.as_ref().unwrap();
    assert_eq!(live.ordinals.len(), 1);
    assert_eq!(live.ordinals["/chat"], 12_553);
    assert!(
        live.counts.is_empty(),
        "unrelated names must not be retained"
    );
    for namespace in 1..64 {
        ingress
            .observe(
                "case",
                epoch,
                &event(&format!("/room-{namespace}"), "notice", 1),
            )
            .unwrap();
    }
    assert!(
        ingress
            .observe("case", epoch, &event("/room-64", "notice", 1))
            .is_err()
    );
    assert_eq!(ingress.observed.as_ref().unwrap().ordinals.len(), 64);
    ingress
        .observe("case", epoch, &event("/chat", "notice", 12_554))
        .unwrap();
}

#[test]
fn maximum_ordinal_never_wraps_into_a_valid_observation() {
    let epoch = Utc::now();
    let mut ingress = Ingress::default();
    assert!(ingress.observe_begin("case", epoch, true));
    ingress
        .observed
        .as_mut()
        .unwrap()
        .ordinals
        .insert("/chat".into(), u64::MAX - 1);
    ingress
        .observe("case", epoch, &event("/chat", "notice", u64::MAX))
        .unwrap();
    assert!(
        ingress
            .observe("case", epoch, &event("/chat", "notice", 0))
            .is_err()
    );
    assert_eq!(
        ingress.observed.as_ref().unwrap().ordinals["/chat"],
        u64::MAX
    );
}
