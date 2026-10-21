use super::*;
use serde_json::json;

pub(in crate::replay) fn protocol_snapshot(
    report: &Path,
    protocol: &str,
    layout: Vec<usize>,
    rows: &[Row],
    snapshot: (usize, Vec<Change>),
    extras: Vec<Row>,
) -> (usize, Vec<Value>) {
    let identity = Identity {
        source_sha256: super::super::artifact::digest(&rows).unwrap(),
        source_bytes: 1000,
        policy: "protocol-differential".into(),
        protocol: protocol.into(),
        layout,
        semantics: Identity::current_semantics(protocol),
    };
    let baseline = RegularBaseline::retain(report, identity, |visit| {
        for row in rows {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    let evidence =
        RegularEvidence::from_live_snapshot(report, &baseline, snapshot, extras).unwrap();
    evidence.validate_protocol(report, protocol).unwrap();
    let count = evidence.count().unwrap();
    let mut items = Vec::new();
    evidence.read(report, 0, count, &mut items).unwrap();
    (count, items)
}

fn identity(protocol: &str) -> Identity {
    Identity {
        source_sha256: "1".repeat(64),
        source_bytes: 1000,
        policy: "policy-v1".into(),
        protocol: protocol.into(),
        layout: if protocol == "kafka" {
            vec![3, 3, 3]
        } else {
            vec![1024]
        },
        semantics: Identity::current_semantics(protocol),
    }
}

#[test]
fn historical_identity_keys_survive_and_only_new_mysql_semantics_change_the_key() {
    #[derive(serde::Serialize)]
    struct LegacyIdentity {
        source_sha256: String,
        source_bytes: u64,
        policy: String,
        protocol: String,
        layout: Vec<usize>,
    }
    for protocol in super::super::PROTOCOLS {
        let legacy = LegacyIdentity {
            source_sha256: "1".repeat(64),
            source_bytes: 1000,
            policy: "policy-v1".into(),
            protocol: protocol.into(),
            layout: vec![1024],
        };
        let original = serde_json::to_value(&legacy).unwrap();
        let historical: Identity = serde_json::from_value(original.clone()).unwrap();
        assert!(historical.semantics.is_none());
        assert_eq!(serde_json::to_value(&historical).unwrap(), original);
        let old_key = super::super::artifact::digest(&(
            "global-regular-projection",
            1_u32,
            "global-before-case-v1",
            &legacy,
        ))
        .unwrap();
        assert_eq!(historical.key().unwrap(), old_key, "{protocol}");
        let mut current = historical;
        current.semantics = Identity::current_semantics(protocol);
        if protocol == "mysql" {
            assert_eq!(
                current.semantics.as_deref(),
                Some("mysql-transaction-cleanup-v2")
            );
            assert_ne!(current.key().unwrap(), old_key);
        } else {
            assert_eq!(current.key().unwrap(), old_key, "{protocol}");
        }
    }
}

#[test]
fn new_mysql_visibility_rebuilds_while_historical_report_pages_remain_readable() {
    let temporary = tempfile::tempdir().unwrap();
    let report = temporary.path().join("report.json");
    let mut historical = identity("mysql");
    historical.semantics = None;
    let values = rows(2);
    let old = RegularBaseline::retain(&report, historical, |visit| {
        for row in &values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(old.visible, 1);
    let current = RegularBaseline::retain(&report, identity("mysql"), |visit| {
        for row in &values {
            let mut row = row.clone();
            row.visible = false;
            visit(row)?;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(current.visible, 0);
    assert_ne!(current.reference.key(), old.reference.key());
    let mut usage = Usage::default();
    usage.initialize(old.visible);
    let old_report = RegularEvidence::from_usage(&report, &old, &usage).unwrap();
    old_report.validate_protocol(&report, "mysql").unwrap();
    let mut restored = Vec::new();
    old_report.read(&report, 0, 1, &mut restored).unwrap();
    assert_eq!(restored, vec![values[1].value.clone()]);
}

fn rows(count: usize) -> Vec<Row> {
    (0..count)
        .map(|index| Row {
            position: Position { section: 0, index },
            visible: index % 5 != 0,
            value: json!({"index":index,"command":"native","stable":format!("record-{index}")}),
        })
        .collect()
}

fn baseline(report: &Path, values: &[Row]) -> RegularBaseline {
    RegularBaseline::retain(report, identity("mysql"), |visit| {
        for row in values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap()
}

#[test]
fn standalone_baseline_rebinds_when_final_report_uses_another_directory() {
    let temp = tempfile::tempdir().unwrap();
    let origin = temp.path().join("case/.replay/replay-report.json");
    let values = rows(3);
    let base = baseline(&origin, &values);
    let mut usage = Usage::default();
    usage.initialize(base.visible);
    usage.observe(0, 1, true, false);
    let report = temp.path().join("published/reports/replay.json");
    let evidence = RegularEvidence::from_usage(&report, &base, &usage).unwrap();
    std::fs::remove_dir_all(origin.parent().unwrap()).unwrap();
    let mut actual = Vec::new();
    evidence.read(&report, 0, 10, &mut actual).unwrap();
    assert_eq!(actual, vec![values[2].value.clone()]);
    assert_eq!(evidence.count().unwrap(), 1);
}

#[test]
fn shared_regular_pages_preserve_native_order_and_optional_visibility_at_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let values = rows(600);
    let base = baseline(&report, &values);
    let mut usage = Usage::default();
    usage.initialize(base.visible);
    usage.observe(0, 3, true, false);
    usage.observe(0, 5, false, true);
    usage.observe(0, 256, true, false);
    let evidence = RegularEvidence::from_usage(&report, &base, &usage).unwrap();
    let expected = values
        .iter()
        .filter(|row| match row.position.index {
            3 | 256 => false,
            5 => true,
            _ => row.visible,
        })
        .map(|row| row.value.clone())
        .collect::<Vec<_>>();
    assert_eq!(evidence.count().unwrap(), expected.len());
    evidence.validate_protocol(&report, "mysql").unwrap();
    assert!(evidence.validate_protocol(&report, "redis").is_err());
    for offset in [
        0,
        1,
        203,
        204,
        205,
        255,
        256,
        expected.len() - 1,
        expected.len(),
    ] {
        let mut actual = Vec::new();
        evidence.read(&report, offset, 4, &mut actual).unwrap();
        assert_eq!(
            actual,
            expected[offset..expected.len().min(offset + 4)],
            "offset={offset}"
        );
    }
    assert!(
        evidence
            .read(&report, expected.len() + 1, 1, &mut vec![])
            .is_err()
    );
    // An unused optional field that fails can reappear, then return to the
    // immutable hidden baseline without consuming or editing Source evidence.
    usage.observe(0, 5, false, false);
    let evidence = RegularEvidence::from_usage(&report, &base, &usage).unwrap();
    assert_eq!(evidence.count().unwrap(), expected.len() - 1);
}

#[test]
fn warm_regular_inventory_does_not_visit_source_and_sessions_do_not_share_consumption() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let values = rows(16);
    let first = baseline(&report, &values);
    let second = RegularBaseline::retain(&report, identity("mysql"), |_| {
        panic!("warm inventory traversed the source")
    })
    .unwrap();
    let mut first_usage = Usage::default();
    first_usage.initialize(first.visible);
    first_usage.observe(0, 1, true, false);
    let first_evidence = RegularEvidence::from_usage(&report, &first, &first_usage).unwrap();
    let mut second_usage = Usage::default();
    second_usage.initialize(second.visible);
    let second_evidence = RegularEvidence::from_usage(&report, &second, &second_usage).unwrap();
    assert_eq!(
        second_evidence.count().unwrap(),
        first_evidence.count().unwrap() + 1
    );
    let mut changed = identity("mysql");
    changed.policy = "policy-v2".into();
    let called = std::cell::Cell::new(false);
    RegularBaseline::retain(&report, changed, |visit| {
        called.set(true);
        for row in &values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    assert!(called.get());
}

#[test]
fn regular_projection_export_survives_source_removal_and_rejects_changed_pages() {
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let source_report = source.path().join("report.json");
    let destination_report = destination.path().join("report.json");
    let values = rows(600);
    let base = baseline(&source_report, &values);
    let mut usage = Usage::default();
    usage.initialize(base.visible);
    let evidence = RegularEvidence::from_usage(&source_report, &base, &usage).unwrap();
    let exported = evidence.stage(&source_report, &destination_report).unwrap();
    source.close().unwrap();
    let mut actual = Vec::new();
    exported
        .read(&destination_report, 204, 4, &mut actual)
        .unwrap();
    let expected = values
        .iter()
        .filter(|row| row.visible)
        .map(|row| row.value.clone())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected[204..208]);
    let (inventory, root) = exported
        .inventory
        .load::<Inventory>(&destination_report)
        .unwrap();
    let mut page = inventory.read_page(&root, 0).unwrap();
    page[1].value["stable"] = json!("changed");
    // Even a rewritten page with a freshly valid storage checksum must remain
    // bound to the immutable page digest in the shared inventory manifest.
    crate::dependency_index::store::write_json(&root.join("0.json"), &page).unwrap();
    assert!(
        exported
            .read(&destination_report, 0, 1, &mut vec![])
            .is_err()
    );
}

#[test]
fn regular_visibility_rejects_duplicates_foreign_positions_and_forged_counts() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let values = rows(16);
    let base = baseline(&report, &values);
    let mut usage = Usage::default();
    usage.initialize(base.visible);
    usage.observe(0, 1, true, false);
    let valid = RegularEvidence::from_usage(&report, &base, &usage).unwrap();
    let mut invalid = valid.clone();
    invalid.changes.push(invalid.changes[0]);
    assert!(invalid.load(&report).is_err());
    let mut invalid = valid.clone();
    invalid.changes[0].position.section = 1;
    assert!(invalid.load(&report).is_err());
    let mut invalid = valid.clone();
    invalid.changes[0].before = false;
    invalid.changes[0].after = true;
    assert!(invalid.load(&report).is_err());
    let mut invalid = valid;
    invalid.remaining += 1;
    assert!(invalid.load(&report).is_err());
}

#[test]
fn kafka_sections_keep_independent_native_indexes_and_order() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let values = (0..3)
        .flat_map(|section| {
            (0..3).map(move |index| Row {
        position: Position { section, index }, visible: true,
        value: json!({"index":index,"operation":(["produce","fetch","delivery"][section as usize])})
    })
        })
        .collect::<Vec<_>>();
    let base = RegularBaseline::retain(&report, identity("kafka"), |visit| {
        for row in &values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    let mut usage = Usage::default();
    usage.initialize(9);
    usage.observe(1, 0, true, false);
    let evidence = RegularEvidence::from_usage(&report, &base, &usage).unwrap();
    let mut page = Vec::new();
    evidence.read(&report, 2, 4, &mut page).unwrap();
    assert_eq!(
        page,
        vec![
            values[2].value.clone(),
            values[4].value.clone(),
            values[5].value.clone(),
            values[6].value.clone()
        ]
    );
}

#[test]
fn case_derived_global_aliases_keep_session_indexes_without_duplicating_shared_rows() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let mut identity = identity("redis");
    identity.layout = vec![2, 2];
    let values = (0..2)
        .flat_map(|section| {
            (0..2).map(move |index| Row {
                position: Position { section, index },
                visible: true,
                value: json!({"section":section,"index":index,"kind":"recorded-global"}),
            })
        })
        .collect::<Vec<_>>();
    let mut first = RegularBaseline::retain(&report, identity.clone(), |visit| {
        for row in &values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    first.extras.push(Row {
        position: Position {
            section: 0,
            index: 5,
        },
        visible: true,
        value: json!({"section":0,"index":5,"kind":"source-case-subscription-alias"}),
    });
    first.visible += 1;
    let mut first_usage = Usage::default();
    first_usage.initialize(5);
    let first_evidence = RegularEvidence::from_usage(&report, &first, &first_usage).unwrap();
    let mut page = Vec::new();
    first_evidence.read(&report, 1, 3, &mut page).unwrap();
    assert_eq!(
        page,
        [
            values[1].value.clone(),
            first.extras[0].value.clone(),
            values[2].value.clone()
        ]
    );
    first_usage.observe(0, 5, true, false);
    let consumed = RegularEvidence::from_usage(&report, &first, &first_usage).unwrap();
    let mut page = Vec::new();
    consumed.read(&report, 1, 3, &mut page).unwrap();
    assert_eq!(
        page,
        [
            values[1].value.clone(),
            values[2].value.clone(),
            values[3].value.clone()
        ]
    );
    let mut second = RegularBaseline::retain(&report, identity, |_| {
        panic!("another API copied the Global baseline")
    })
    .unwrap();
    second.extras.push(Row {
        position: Position {
            section: 0,
            index: 9,
        },
        visible: true,
        value: json!({"section":0,"index":9,"kind":"source-case-subscription-alias"}),
    });
    second.visible += 1;
    assert_eq!(first.reference.key(), second.reference.key());
    let mut second_usage = Usage::default();
    second_usage.initialize(5);
    let second_evidence = RegularEvidence::from_usage(&report, &second, &second_usage).unwrap();
    let mut page = Vec::new();
    second_evidence.read(&report, 2, 1, &mut page).unwrap();
    assert_eq!(page, [second.extras[0].value.clone()]);
    let mut forged = second_evidence;
    forged.extras[0].position.index = 1;
    assert!(forged.validate_protocol(&report, "redis").is_err());
}

#[test]
fn cursor_composes_both_sections_extras_and_visibility_additions_without_reordering() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let mut identity = identity("redis");
    identity.layout = vec![2, 2];
    let values = (0..2)
        .flat_map(|section| {
            (0..2).map(move |index| Row {
                position: Position { section, index },
                visible: index != 0,
                value: json!({"section":section,"index":index,"origin":"global"}),
            })
        })
        .collect::<Vec<_>>();
    let mut base = RegularBaseline::retain(&report, identity, |visit| {
        for row in &values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    base.extras = vec![
        Row {
            position: Position {
                section: 0,
                index: 5,
            },
            visible: true,
            value: json!({"section":0,"index":5,"origin":"extra"}),
        },
        Row {
            position: Position {
                section: 1,
                index: 6,
            },
            visible: false,
            value: json!({"section":1,"index":6,"origin":"extra"}),
        },
    ];
    base.visible += 1;
    let mut usage = Usage::default();
    usage.initialize(base.visible);
    usage.observe(0, 0, false, true);
    usage.observe(1, 1, true, false);
    usage.observe(1, 6, false, true);
    let evidence = RegularEvidence::from_usage(&report, &base, &usage).unwrap();
    let expected = [
        values[0].value.clone(),
        values[1].value.clone(),
        base.extras[0].value.clone(),
        base.extras[1].value.clone(),
    ];
    assert_eq!(evidence.count().unwrap(), expected.len());
    for offset in 0..=expected.len() {
        let mut actual = Vec::new();
        evidence.read(&report, offset, 3, &mut actual).unwrap();
        assert_eq!(actual, expected[offset..expected.len().min(offset + 3)]);
    }
}

#[test]
fn aliases_added_after_initialization_are_collected_from_the_live_session_tail() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("report.json");
    let mut identity = identity("redis");
    identity.layout = vec![2];
    let values = rows(2);
    let base = RegularBaseline::retain(&report, identity, |visit| {
        for row in &values {
            visit(row.clone())?;
        }
        Ok(())
    })
    .unwrap();
    let mut usage = Usage::default();
    usage.freeze_layout(vec![2]);
    usage.initialize(base.visible);
    let extra = Row {
        position: Position {
            section: 0,
            index: 8,
        },
        visible: true,
        value: json!({"index":8,"command":"SUBSCRIBE","origin":"late-source-case-alias"}),
    };
    let evidence = RegularEvidence::from_live_snapshot(
        &report,
        &base,
        usage.snapshot().unwrap(),
        vec![extra.clone()],
    )
    .unwrap();
    assert_eq!(evidence.count().unwrap(), base.visible + 1);
    usage.observe(0, 8, true, false);
    usage.observe(0, 8, true, false);
    assert_eq!(usage.count(), Some(base.visible));
    let evidence =
        RegularEvidence::from_live_snapshot(&report, &base, usage.snapshot().unwrap(), vec![extra])
            .unwrap();
    assert_eq!(evidence.count().unwrap(), base.visible);
    let mut actual = Vec::new();
    evidence.read(&report, 0, 10, &mut actual).unwrap();
    assert_eq!(
        actual,
        values
            .into_iter()
            .filter(|row| row.visible)
            .map(|row| row.value)
            .collect::<Vec<_>>()
    );
}
