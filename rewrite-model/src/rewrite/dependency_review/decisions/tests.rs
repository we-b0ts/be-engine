//! Compact storage keeps every occurrence and historical decision without proof duplication.
use super::*;

fn template(name: &str, revision: u64) -> DecisionTemplate {
    DecisionTemplate {
        owner:DependencyOwner::Process{process_epoch:Uuid::from_u128(1),source_task:name.into(),invocation:None},
        proof_id:format!("proof-{name}"),proof_revision:revision,
        proof:AttributionProof{source_revision:"source-revision".into(),source_locations:vec!["source/redis.py:listen".into()],
            call_chain:"The Source-owned receive loop forwards actual notifications independently of request handlers. ".repeat(8),
            exclusive_scope:"One authenticated Source subscription in the exact process epoch".into()},
        rule_bindings:BTreeMap::from([(format!("task-{name}"),"rule-fingerprint".into())]),
    }
}
fn group(name: &str, revision: u64, ids: impl IntoIterator<Item = u128>) -> Arc<DecisionGroup> {
    Arc::new(DecisionGroup {
        template: template(name, revision),
        exchange_ids: ids.into_iter().map(Uuid::from_u128).collect(),
    })
}
fn history_items(history: &DecisionHistory) -> Vec<AttributionDecision> {
    history
        .groups
        .iter()
        .flat_map(|group| {
            group
                .exchange_ids
                .iter()
                .map(|id| group.template.decision(*id))
        })
        .collect()
}

#[test]
fn a_large_inventory_and_history_share_immutable_templates_and_all_source_ids() {
    let group = group("subscriber", 2, 1..=203_425);
    let mut active = DecisionSet::default();
    active.insert_group(group.clone()).unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(group.clone());
    assert_eq!(active.len(), 203_425);
    assert_eq!(history.len(), 203_425);
    let copied = active.clone();
    let copied_history = history.clone();
    assert!(Arc::ptr_eq(&active.groups[0], &copied.groups[0]));
    assert!(Arc::ptr_eq(&history.groups[0], &copied_history.groups[0]));
    assert!(Arc::ptr_eq(&active.groups[0], &history.groups[0]));
    assert_eq!(active.templates().count(), 1);
    let payload = serde_json::to_vec(&(active, history)).unwrap();
    assert!(
        payload.len() < 20 * 1024 * 1024,
        "proof text must not repeat per occurrence: {}",
        payload.len()
    );
    let (restored, old): (DecisionSet, DecisionHistory) = serde_json::from_slice(&payload).unwrap();
    assert_eq!(restored.len(), 203_425);
    assert_eq!(old.len(), 203_425);
    assert!(restored.contains_key(&Uuid::from_u128(203_425)));
    assert!(!restored.contains_key(&Uuid::from_u128(203_426)));
    assert_eq!(restored.templates().count(), 1);
}

#[test]
fn legacy_maps_stream_into_shared_groups_and_write_compact_state() {
    let proof = template("subscriber", 7);
    let original = (1..=128)
        .map(|id| {
            let id = Uuid::from_u128(id);
            (id, proof.decision(id))
        })
        .collect::<BTreeMap<_, _>>();
    let legacy = serde_json::to_vec(&original).unwrap();
    let compact: DecisionSet = serde_json::from_slice(&legacy).unwrap();
    assert_eq!(compact.len(), 128);
    assert_eq!(compact.templates().count(), 1);
    for (id, decision) in &original {
        assert_eq!(compact.get(id).unwrap().decision(*id), *decision);
    }
    let saved = serde_json::to_vec(&compact).unwrap();
    assert!(saved.len() * 10 < legacy.len());
    let restored: DecisionSet = serde_json::from_slice(&saved).unwrap();
    assert_eq!(restored.len(), original.len());
}

#[test]
fn legacy_history_keeps_order_repeated_occurrences_and_prior_revisions() {
    let first = template("first", 1);
    let second = template("second", 2);
    let original = vec![
        first.decision(Uuid::from_u128(2)),
        first.decision(Uuid::from_u128(1)),
        second.decision(Uuid::from_u128(3)),
        first.decision(Uuid::from_u128(2)),
    ];
    let history: DecisionHistory =
        serde_json::from_value(serde_json::to_value(&original).unwrap()).unwrap();
    assert_eq!(history_items(&history), original);
    let restored: DecisionHistory =
        serde_json::from_value(serde_json::to_value(&history).unwrap()).unwrap();
    assert_eq!(history_items(&restored), original);
}

#[test]
fn changing_one_scope_keeps_untouched_occurrences_and_immutable_history() {
    let original = group("original", 1, 1..=4);
    let replacement = group("replacement", 2, 2..=3);
    let mut active = DecisionSet::default();
    let mut history = DecisionHistory::default();
    active.insert_group(original.clone()).unwrap();
    history.push_group(original.clone());
    let snapshot = active.clone();
    active.insert_group(replacement.clone()).unwrap();
    history.push_group(replacement);
    assert_eq!(active.len(), 4);
    assert_eq!(history.len(), 6);
    assert_eq!(
        active.get(&Uuid::from_u128(1)).unwrap().proof_id,
        "proof-original"
    );
    assert_eq!(
        active.get(&Uuid::from_u128(2)).unwrap().proof_id,
        "proof-replacement"
    );
    assert_eq!(
        snapshot.get(&Uuid::from_u128(2)).unwrap().proof_id,
        "proof-original"
    );
    assert!(Arc::ptr_eq(&history.groups[0], &original));
    let removed = active.retain_groups(|template| template.proof_id != "proof-replacement");
    assert_eq!(removed.len(), 1);
    assert!(removed[0].contains(&Uuid::from_u128(3)));
    assert_eq!(active.len(), 2);
    assert_eq!(history.len(), 6);
}

#[test]
fn duplicate_source_ids_conflicting_templates_and_mismatched_legacy_keys_are_rejected() {
    let first = group("same", 1, 1..=2);
    let mut duplicate = serde_json::to_value(&*first).unwrap();
    duplicate["exchange_ids"] = serde_json::json!([Uuid::from_u128(2), Uuid::from_u128(3)]);
    assert!(
        serde_json::from_value::<DecisionSet>(
            serde_json::json!({"format":"dependency-decisions/v1","groups":[&*first,duplicate]})
        )
        .is_err()
    );
    let mut conflict = serde_json::to_value(&*first).unwrap();
    conflict["exchange_ids"] = serde_json::json!([Uuid::from_u128(3)]);
    conflict["template"]["proof"]["exclusive_scope"] = serde_json::json!("different provenance");
    assert!(
        serde_json::from_value::<DecisionSet>(
            serde_json::json!({"format":"dependency-decisions/v1","groups":[&*first,conflict]})
        )
        .is_err()
    );
    let mismatch = BTreeMap::from([(
        Uuid::from_u128(3),
        first.template.decision(Uuid::from_u128(2)),
    )]);
    assert!(
        serde_json::from_value::<DecisionSet>(serde_json::to_value(mismatch).unwrap()).is_err()
    );
    let id = Uuid::from_u128(1);
    let entry = serde_json::to_string(&first.template.decision(id)).unwrap();
    assert!(
        serde_json::from_str::<DecisionSet>(&format!("{{\"{id}\":{entry},\"{id}\":{entry}}}"))
            .is_err()
    );
}

#[test]
fn invalidated_rules_drop_whole_groups_without_expanding_or_losing_history() {
    let group = group("subscriber", 1, 1..=2048);
    let mut active = DecisionSet::default();
    active.insert_group(group.clone()).unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(group);
    let rules = BTreeMap::new();
    let removed = active.retain_groups(|template| {
        crate::rewrite::dependency_review::rules::current(template, &rules)
    });
    assert!(active.is_empty());
    assert_eq!(removed[0].exchange_ids.len(), 2048);
    assert_eq!(history.len(), 2048);
    assert_eq!(history.groups.len(), 1);
}

#[test]
fn historical_proof_revisions_may_repeat_an_occurrence_but_cannot_contradict_the_same_proof() {
    let first = template("same", 1);
    let mut changed = first.clone();
    changed.proof_revision = 2;
    let entries = vec![
        first.decision(Uuid::from_u128(1)),
        changed.decision(Uuid::from_u128(1)),
    ];
    let restored: DecisionHistory =
        serde_json::from_value(serde_json::to_value(&entries).unwrap()).unwrap();
    assert_eq!(history_items(&restored), entries);
    changed.proof_revision = 1;
    changed.proof.exclusive_scope = "a contradictory provenance".into();
    assert!(
        serde_json::from_value::<DecisionHistory>(
            serde_json::to_value(vec![
                first.decision(Uuid::from_u128(1)),
                changed.decision(Uuid::from_u128(2))
            ])
            .unwrap()
        )
        .is_err()
    );
}

#[test]
fn canonical_snapshot_is_independent_of_group_insertion_order_and_never_projects_occurrence_dtos() {
    let first = group("first", 1, 1..=100_000);
    let second = group("second", 2, 100_001..=203_425);
    let mut a = DecisionSet::default();
    a.insert_group(first.clone()).unwrap();
    a.insert_group(second.clone()).unwrap();
    let mut b = DecisionSet::default();
    b.insert_group(second).unwrap();
    b.insert_group(first).unwrap();
    DTO_PROJECTIONS.with(|count| count.set(0));
    let identity = a
        .snapshot(
            "recording",
            Some("source-revision"),
            "sealed-source",
            |_| true,
        )
        .unwrap();
    assert_eq!(
        identity,
        b.snapshot(
            "recording",
            Some("source-revision"),
            "sealed-source",
            |_| true
        )
        .unwrap()
    );
    assert_eq!(DTO_PROJECTIONS.with(std::cell::Cell::get), 0);
}

#[test]
fn snapshot_binds_every_source_member_proof_rule_source_revision_and_inventory() {
    let original = group("source", 1, 1..=4);
    let mut active = DecisionSet::default();
    active.insert_group(original.clone()).unwrap();
    let identity = active
        .snapshot("recording", Some("source-revision"), "inventory", |_| true)
        .unwrap();
    for changed in [
        active
            .snapshot("other-run", Some("source-revision"), "inventory", |_| true)
            .unwrap(),
        active
            .snapshot("recording", Some("other-source"), "inventory", |_| true)
            .unwrap(),
        active
            .snapshot(
                "recording",
                Some("source-revision"),
                "different-inventory",
                |_| true,
            )
            .unwrap(),
        active
            .snapshot("recording", Some("source-revision"), "inventory", |_| false)
            .unwrap(),
    ] {
        assert_ne!(identity, changed);
    }
    for change in 0..3 {
        let mut group = (*original).clone();
        match change {
            0 => {
                group.exchange_ids.pop();
            }
            1 => group
                .template
                .proof
                .call_chain
                .push_str(" changed actual Source caller"),
            _ => {
                group
                    .template
                    .rule_bindings
                    .insert("another-rule".into(), "fingerprint".into());
            }
        }
        let changed = DecisionSet {
            groups: vec![Arc::new(group)],
        };
        assert_ne!(
            identity,
            changed
                .snapshot("recording", Some("source-revision"), "inventory", |_| true)
                .unwrap()
        );
    }
}

#[test]
fn split_compact_groups_normalize_to_the_same_finite_ownership_snapshot() {
    let whole = group("same", 1, 1..=4);
    let first = group("same", 1, 1..=2);
    let last = group("same", 1, 3..=4);
    let split: DecisionSet = serde_json::from_value(
        serde_json::json!({"format":"dependency-decisions/v1","groups":[&*last,&*first]}),
    )
    .unwrap();
    assert_eq!(split.templates().count(), 1);
    assert_eq!(split.len(), 4);
    let unsplit: DecisionSet = serde_json::from_value(
        serde_json::json!({"format":"dependency-decisions/v1","groups":[&*whole]}),
    )
    .unwrap();
    assert_eq!(
        split
            .snapshot("recording", Some("source-revision"), "inventory", |_| true)
            .unwrap(),
        unsplit
            .snapshot("recording", Some("source-revision"), "inventory", |_| true)
            .unwrap()
    );
}
