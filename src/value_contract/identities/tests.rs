use super::*;
use serde_json::json;

fn pair(domain: &str, source: &str, target: &str) -> IdentityPair {
    IdentityPair {
        domain: domain.into(),
        source: source.into(),
        target: target.into(),
    }
}

fn decision(case: &str, pairs: Vec<IdentityPair>) -> IdentityDecision {
    IdentityDecision::prepare(case, pairs).unwrap()
}

#[test]
fn accepted_relations_span_observations_and_preserve_distinct_entities() {
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("task", "1", "101")]))
        .unwrap();
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "1", "101")]))
            .is_ok()
    );
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "1", "102")]))
            .is_err()
    );
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "2", "101")]))
            .is_err()
    );
    // The same literal in another explicitly declared identity domain is independent.
    store
        .commit(decision("case", vec![pair("session", "1", "102")]))
        .unwrap();
    store
        .commit(decision("other", vec![pair("task", "1", "103")]))
        .unwrap();
    store.begin_case("case");
    assert!(!store.has_case("case"));
    assert!(store.has_case("other"));
    store
        .commit(decision("case", vec![pair("task", "1", "104")]))
        .unwrap();
}

#[test]
fn failed_candidates_and_stale_commits_do_not_publish_partial_bindings() {
    let mut store = IdentityStore::default();
    let stale = decision(
        "case",
        vec![pair("task", "2", "102"), pair("task", "1", "101")],
    );
    store.validate(&stale).unwrap();
    assert!(!store.has_case("case"));
    store
        .commit(decision("case", vec![pair("task", "1", "999")]))
        .unwrap();
    assert!(store.commit(stale).is_err());
    // The first pair in the failed transaction must not reserve Target 102.
    store
        .commit(decision("case", vec![pair("task", "3", "102")]))
        .unwrap();
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "2", "102")]))
            .is_err()
    );
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "2", "103")]))
            .is_ok()
    );
}

#[test]
fn proposal_overlay_rejects_equal_source_splits_and_distinct_source_collapses() {
    let store = IdentityStore::default();
    for pairs in [
        vec![pair("task", "1", "101"), pair("task", "1", "102")],
        vec![pair("task", "1", "101"), pair("task", "2", "101")],
    ] {
        assert!(store.validate(&decision("case", pairs)).is_err());
    }
    assert!(!store.has_case("case"));
}

#[test]
fn read_delivery_uses_known_renaming_and_fixes_unknown_historical_entities() {
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("task", "11", "1011")]))
        .unwrap();
    let old = json!("task_11");
    let historical = json!(12);
    let prepared = [
        PreparedIdentityDelivery::prepare(IdentityDelivery {
            binding: "task",
            prefix: "task_",
            format: IdentityFormat::Decimal,
            value: &old,
        })
        .unwrap(),
        PreparedIdentityDelivery::prepare(IdentityDelivery {
            binding: "task",
            prefix: "",
            format: IdentityFormat::Decimal,
            value: &historical,
        })
        .unwrap(),
    ];
    let (values, pending) = store.deliveries("case", &prepared).unwrap();
    assert_eq!(values, vec![json!("task_1011"), json!(12)]);
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "12", "1012")]))
            .is_ok()
    );
    store.commit(pending).unwrap();
    assert!(
        store
            .validate(&decision("case", vec![pair("task", "12", "1012")]))
            .is_err()
    );
}

#[test]
fn independent_deliveries_cannot_silently_collapse_a_historical_id_into_known_target() {
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("task", "11", "1011")]))
        .unwrap();
    let historical = json!("1011");
    let prepared = PreparedIdentityDelivery::prepare(IdentityDelivery {
        binding: "task",
        prefix: "",
        format: IdentityFormat::Decimal,
        value: &historical,
    })
    .unwrap();
    assert!(store.deliveries("case", &[prepared]).is_err());
}

#[test]
fn entity_limit_counts_across_domains_and_cleanup_releases_capacity() {
    let mut store = IdentityStore::default();
    let pairs = (0..MAX_CASE_ENTITIES)
        .map(|index| {
            pair(
                if index % 2 == 0 { "task" } else { "session" },
                &(index + 1).to_string(),
                &(index + 10001).to_string(),
            )
        })
        .collect();
    store.commit(decision("case", pairs)).unwrap();
    store
        .commit(decision("case", vec![pair("task", "1", "10001")]))
        .unwrap();
    assert!(
        store
            .commit(decision("case", vec![pair("third", "1", "10001")]))
            .is_err()
    );
    store.begin_case("case");
    store
        .commit(decision("case", vec![pair("third", "1", "10001")]))
        .unwrap();
}

#[test]
fn private_tokens_do_not_appear_in_debug_output() {
    let pair = pair("task", "private-source-id", "private-target-id");
    assert!(!format!("{pair:?}").contains("private-source"));
    let decision = decision("case", vec![pair]);
    assert!(!format!("{decision:?}").contains("private-target"));
    let mut store = IdentityStore::default();
    store.commit(decision).unwrap();
    assert!(!format!("{store:?}").contains("private-target"));
}

#[test]
fn selector_bounds_stop_large_arrays_before_collecting_unbounded_paths() {
    let root = json!({"items": (0..5000).map(|_| json!({"id":"1"})).collect::<Vec<_>>()});
    assert!(selected_pointers("/items/*/id", &root, &mut 16384).is_err());
    let root = json!({"items": (0..20000).map(|_| json!({})).collect::<Vec<_>>()});
    assert!(selected_pointers("/items/*/id", &root, &mut 16384).is_err());
    assert_eq!(
        selected_pointers("/items/1", &json!({"items":[1,2,3]}), &mut 10).unwrap(),
        vec!["/items/1"]
    );
}

#[test]
#[ignore = "manual identity state scaling measurement"]
fn benchmark_repeated_identity_validation_retains_bounded_state() {
    for count in [512, 1024, 2048, 4096] {
        let mut store = IdentityStore::default();
        let proposal = decision(
            "case",
            (1..=count)
                .map(|index| pair("entity", &index.to_string(), &(index + 10000).to_string()))
                .collect(),
        );
        store.commit(proposal.clone()).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..32 {
            store.commit(proposal.clone()).unwrap();
        }
        assert_eq!(store.entities, count);
        assert_eq!(store.cases["case"].domains["entity"].forward.len(), count);
        eprintln!(
            "{count} identity pairs, 32 accepted batches: {:?}",
            started.elapsed()
        );
        store.begin_case("case");
        assert_eq!(store.entities, 0);
    }
}
