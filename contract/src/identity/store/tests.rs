use super::*;
use crate::rule::IdentityFormat;
use serde_json::json;

mod custom_policy;

fn pair(source: &str, target: &str) -> IdentityPair {
    IdentityPair {
        source: serde_json::to_string(source).unwrap(),
        target: serde_json::to_string(target).unwrap(),
    }
}

fn decision(case: &str, pairs: Vec<IdentityPair>) -> IdentityDecision {
    IdentityDecision::prepare(case, pairs).unwrap()
}

#[test]
fn accepted_relations_span_observations_and_preserve_distinct_entities() {
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("1", "101")]))
        .unwrap();
    assert!(
        store
            .validate(&decision("case", vec![pair("1", "101")]))
            .is_ok()
    );
    assert!(
        store
            .validate(&decision("case", vec![pair("1", "102")]))
            .is_err()
    );
    assert!(
        store
            .validate(&decision("case", vec![pair("2", "101")]))
            .is_err()
    );
    // Every declared position shares the same relation, without named domains.
    assert!(
        store
            .commit(decision("case", vec![pair("1", "102")]))
            .is_err()
    );
    store
        .commit(decision("other", vec![pair("1", "103")]))
        .unwrap();
    store.begin_case("case");
    assert!(!store.has_case("case"));
    assert!(store.has_case("other"));
    store
        .commit(decision("case", vec![pair("1", "104")]))
        .unwrap();
}

#[test]
fn failed_candidates_and_stale_commits_do_not_publish_partial_bindings() {
    let mut store = IdentityStore::default();
    let stale = decision("case", vec![pair("2", "102"), pair("1", "101")]);
    store.validate(&stale).unwrap();
    assert!(!store.has_case("case"));
    store
        .commit(decision("case", vec![pair("1", "999")]))
        .unwrap();
    assert!(store.commit(stale).is_err());
    // The first pair in the failed transaction must not reserve Target 102.
    store
        .commit(decision("case", vec![pair("3", "102")]))
        .unwrap();
    assert!(
        store
            .validate(&decision("case", vec![pair("2", "102")]))
            .is_err()
    );
    assert!(
        store
            .validate(&decision("case", vec![pair("2", "103")]))
            .is_ok()
    );
}

#[test]
fn proposal_overlay_rejects_equal_source_splits_and_distinct_source_collapses() {
    let store = IdentityStore::default();
    for pairs in [
        vec![pair("1", "101"), pair("1", "102")],
        vec![pair("1", "101"), pair("2", "101")],
    ] {
        assert!(store.validate(&decision("case", pairs)).is_err());
    }
    assert!(!store.has_case("case"));
}

#[test]
fn read_delivery_uses_known_renaming_and_fixes_unknown_historical_entities() {
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("task_11", "task_1011")]))
        .unwrap();
    let old = json!("task_11");
    let historical = json!(12);
    let prepared = [
        prepare_delivery(IdentityDelivery {
            prefix: "task_",
            format: IdentityFormat::Decimal,
            value: &old,
        })
        .unwrap(),
        prepare_delivery(IdentityDelivery {
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
            .validate(&decision(
                "case",
                vec![IdentityPair {
                    source: "12".into(),
                    target: "1012".into()
                }]
            ))
            .is_ok()
    );
    store.commit(pending).unwrap();
    assert!(
        store
            .validate(&decision(
                "case",
                vec![IdentityPair {
                    source: "12".into(),
                    target: "1012".into()
                }]
            ))
            .is_err()
    );
}

#[test]
fn independent_deliveries_cannot_silently_collapse_a_historical_id_into_known_target() {
    let mut store = IdentityStore::default();
    store
        .commit(decision("case", vec![pair("11", "1011")]))
        .unwrap();
    let historical = json!("1011");
    let prepared = prepare_delivery(IdentityDelivery {
        prefix: "",
        format: IdentityFormat::Decimal,
        value: &historical,
    })
    .unwrap();
    assert!(store.deliveries("case", &[prepared]).is_err());
}

#[test]
fn entity_limit_counts_all_positions_and_cleanup_releases_capacity() {
    let mut store = IdentityStore::default();
    let pairs = (0..MAX_CASE_ENTITIES)
        .map(|index| pair(&(index + 1).to_string(), &(index + 10001).to_string()))
        .collect();
    store.commit(decision("case", pairs)).unwrap();
    store
        .commit(decision("case", vec![pair("1", "10001")]))
        .unwrap();
    assert!(
        store
            .commit(decision("case", vec![pair("4097", "14097")]))
            .is_err()
    );
    store.begin_case("case");
    store
        .commit(decision("case", vec![pair("1", "10001")]))
        .unwrap();
}

#[test]
fn private_tokens_do_not_appear_in_debug_output() {
    let pair = pair("private-source-id", "private-target-id");
    assert!(!format!("{pair:?}").contains("private-source"));
    let decision = decision("case", vec![pair]);
    assert!(!format!("{decision:?}").contains("private-target"));
    let mut store = IdentityStore::default();
    store.commit(decision).unwrap();
    assert!(!format!("{store:?}").contains("private-target"));
}

#[test]
#[ignore = "manual identity state scaling measurement"]
fn benchmark_repeated_identity_validation_retains_bounded_state() {
    for count in [512, 1024, 2048, 4096] {
        let mut store = IdentityStore::default();
        let proposal = decision(
            "case",
            (1..=count)
                .map(|index| pair(&index.to_string(), &(index + 10000).to_string()))
                .collect(),
        );
        store.commit(proposal.clone()).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..32 {
            store.commit(proposal.clone()).unwrap();
        }
        assert_eq!(store.entities, count);
        assert_eq!(store.cases["case"].forward.len(), count);
        eprintln!(
            "{count} identity pairs, 32 accepted batches: {:?}",
            started.elapsed()
        );
        store.begin_case("case");
        assert_eq!(store.entities, 0);
    }
}

#[test]
fn malformed_or_untyped_private_pairs_are_rejected() {
    for (source, target) in [
        ("unquoted", "other"),
        ("1", "\"2\""),
        ("true", "false"),
        ("null", "null"),
    ] {
        assert!(
            IdentityDecision::prepare(
                "case",
                vec![IdentityPair {
                    source: source.into(),
                    target: target.into()
                }]
            )
            .is_err()
        );
    }
}

#[test]
fn large_tokens_hit_byte_limits_before_entity_limits_and_case_cleanup_releases_bytes() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let token = |index: usize| {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#),
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({"index":index,"padding":"x".repeat(44_000)})).unwrap()
            ),
            URL_SAFE_NO_PAD.encode([0u8; 32])
        )
    };
    let mut store = IdentityStore::default();
    let mut accepted = 0;
    loop {
        let token = token(accepted);
        let proposal = decision("case", vec![pair(&token, &token)]);
        if store.commit(proposal).is_err() {
            break;
        }
        accepted += 1;
        assert!(accepted < MAX_CASE_ENTITIES);
    }
    assert!(accepted > 1);
    let too_many = (0..accepted)
        .map(|index| {
            let token = token(index);
            pair(&token, &token)
        })
        .collect();
    assert!(IdentityDecision::prepare("case", too_many).is_err());
    store.begin_case("case");
    assert_eq!(store.bytes, 0);
    let token = token(accepted);
    store
        .commit(decision("case", vec![pair(&token, &token)]))
        .unwrap();
}

struct IdentityDelivery<'a> {
    prefix: &'a str,
    format: crate::rule::IdentityFormat,
    value: &'a Value,
}
fn prepare_delivery(selected: IdentityDelivery<'_>) -> Result<PreparedIdentityDelivery> {
    let definition = crate::rule::FieldContract::Identity {
        prefix: selected.prefix.into(),
        format: selected.format,
    }
    .registered_definition(false)
    .unwrap();
    PreparedIdentityDelivery::prepare(
        selected.value,
        traffic_extensions::policies().prepare_definition(&definition)?,
    )
}
