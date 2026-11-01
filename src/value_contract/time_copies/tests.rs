use super::*;
use crate::policy::FieldContract;
use crate::value_contract::json::{self, AnchorClocks, Field};
use crate::value_contract::time::ClockPair;
use serde_json::json;

const RULE: &str = "global.json";
fn position() -> TimeCopyPosition<'static> {
    TimeCopyPosition::Mysql {
        host: "db.test",
        port: 3306,
        database: "app",
        table: "tasks",
        column: "payload",
    }
}
fn store() -> TimeCopyStore {
    let mut store = TimeCopyStore::default();
    store.set_record_clocks(ClockPair {
        source: chrono::DateTime::from_timestamp(0, 0),
        target: chrono::DateTime::from_timestamp(0, 0),
    });
    store.set_lookup_clocks(clocks().dependency);
    store
}
fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    }
}
fn contract(format: &str, group: Option<&str>) -> FieldContract {
    serde_json::from_value(
        json!({"kind":"time","format":format,"relation":"preserve_offset","clock_group":group}),
    )
    .unwrap()
}

#[test]
fn delivered_copy_requires_case_position_path_and_exact_pair() {
    let mut store = store();
    let p = position();
    store
        .record("case", p, p, "/t", "/t", &json!(10), &json!(20))
        .unwrap();
    let proof = store
        .proof("case", p, p, "/t", "/t", &json!(10), &json!(20), RULE)
        .unwrap();
    let time = contract("unix_seconds", None);
    let fields = [Field {
        rule_id: RULE,
        pointer: "/t",
        contract: &time,
    }];
    let value = json!({"t":10,"other":1});
    let target = json!({"t":20,"other":1});
    assert!(json::compare(&value, &value, &fields, clocks()).passed());
    assert!(!json::compare(&value, &target, &fields, clocks()).passed());
    assert!(
        json::compare_with_time_copies(
            &value,
            &target,
            &fields,
            clocks(),
            std::slice::from_ref(&proof)
        )
        .passed()
    );
    assert!(
        !json::compare_with_time_copies(
            &value,
            &json!({"t":11,"other":1}),
            &fields,
            clocks(),
            &[proof]
        )
        .passed()
    );
    assert!(
        store
            .proof_for_source("other", p, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
    assert!(
        store
            .proof_for_source("case", p, p, "/other", "/t", &json!(10), RULE)
            .is_none()
    );
    let other = TimeCopyPosition::Mysql {
        host: "db.test",
        port: 3306,
        database: "other",
        table: "tasks",
        column: "payload",
    };
    assert!(
        store
            .proof_for_source("case", other, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), "native-clock")
            .is_none()
    );
    store.begin_case("case");
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
}

#[test]
fn copied_values_still_parse_and_native_clocks_still_shift() {
    let mut store = store();
    let p = position();
    store
        .record("case", p, p, "/t", "/t", &json!("bad"), &json!("bad"))
        .unwrap();
    let proof = store
        .proof_for_source("case", p, p, "/t", "/t", &json!("bad"), RULE)
        .unwrap();
    let time = contract("rfc3339", None);
    let fields = [Field {
        rule_id: RULE,
        pointer: "/t",
        contract: &time,
    }];
    let bad = json!({"t":"bad"});
    assert!(
        json::compare_with_time_copies(&bad, &bad, &fields, clocks(), std::slice::from_ref(&proof))
            .passed()
    );
    assert!(
        !json::compare_with_time_copies(
            &bad,
            &json!({"t":"different"}),
            &fields,
            clocks(),
            &[proof]
        )
        .passed()
    );
    store
        .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
        .unwrap();
    let proof = store
        .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
        .unwrap();
    let time = contract("unix_seconds", None);
    let fields = [
        Field {
            rule_id: RULE,
            pointer: "/t",
            contract: &time,
        },
        Field {
            rule_id: "native-clock",
            pointer: "/t",
            contract: &time,
        },
    ];
    let value = json!({"t":10});
    assert!(!json::compare_with_time_copies(&value, &value, &fields, clocks(), &[proof]).passed());
}

#[test]
fn ambiguity_and_offline_future_delivery_cannot_authorize_a_copy() {
    let mut store = store();
    let p = position();
    let early = chrono::DateTime::from_timestamp(1000, 0).unwrap();
    store.set_record_clocks(ClockPair {
        source: Some(early),
        target: Some(early),
    });
    store
        .record("case", p, p, "/t", "/t", &json!(10), &json!(20))
        .unwrap();
    store.set_lookup_clocks(ClockPair {
        source: Some(early),
        target: Some(early - chrono::TimeDelta::seconds(1)),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
    store.set_lookup_clocks(ClockPair {
        source: Some(early),
        target: Some(early),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_some()
    );
    store
        .record("case", p, p, "/t", "/t", &json!(10), &json!(21))
        .unwrap();
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
}

#[test]
fn chronology_requires_one_real_earlier_read_in_both_executions() {
    let p = position();
    let at = |seconds| chrono::DateTime::from_timestamp(seconds, 0);
    let mut store = store();
    for (source, target) in [(5, 20), (20, 5)] {
        store.set_record_clocks(ClockPair {
            source: at(source),
            target: at(target),
        });
        store
            .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
            .unwrap();
    }
    // Neither read was complete before this write in both executions. Taking
    // the two independent minima would incorrectly invent the pair (5, 5).
    store.set_lookup_clocks(ClockPair {
        source: at(10),
        target: at(10),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
    store.set_lookup_clocks(ClockPair {
        source: at(5),
        target: at(20),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_some()
    );
    store.set_lookup_clocks(ClockPair {
        source: at(20),
        target: at(5),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_some()
    );
    assert_eq!(store.total, 2);
    // A genuinely earlier read dominates both prior observations and reclaims
    // their capacity without composing their clocks.
    store.set_record_clocks(ClockPair {
        source: at(4),
        target: at(4),
    });
    store
        .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
        .unwrap();
    assert_eq!(store.total, 1);
    store.set_lookup_clocks(ClockPair {
        source: at(10),
        target: at(10),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_some()
    );
}

#[test]
fn unknown_read_or_write_clock_never_grants_copy_permission() {
    let p = position();
    for missing_source in [true, false] {
        let mut store = store();
        let known = chrono::DateTime::from_timestamp(1, 0);
        store.set_record_clocks(ClockPair {
            source: if missing_source { None } else { known },
            target: if missing_source { known } else { None },
        });
        store
            .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
            .unwrap();
        assert!(!store.has_case("case"));
        store.set_record_clocks(ClockPair {
            source: known,
            target: known,
        });
        store
            .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
            .unwrap();
        store.set_lookup_clocks(ClockPair {
            source: if missing_source { None } else { known },
            target: if missing_source { known } else { None },
        });
        assert!(
            store
                .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
                .is_none()
        );
    }
}

#[test]
fn delivery_frontier_is_included_in_the_atomic_capacity_bound() {
    let p = position();
    let at = |seconds| chrono::DateTime::from_timestamp(seconds, 0);
    let mut store = store();
    for value in 0..MAX_CASE_COPIES {
        store.set_record_clocks(ClockPair {
            source: at(value as i64),
            target: at((MAX_CASE_COPIES - value) as i64),
        });
        store
            .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
            .unwrap();
    }
    assert_eq!(store.total, MAX_CASE_COPIES);
    store.set_record_clocks(ClockPair {
        source: at(MAX_CASE_COPIES as i64),
        target: at(0),
    });
    assert!(
        store
            .record("case", p, p, "/t", "/t", &json!(10), &json!(10))
            .is_err()
    );
    assert_eq!(store.total, MAX_CASE_COPIES);
    store.set_lookup_clocks(ClockPair {
        source: at(MAX_CASE_COPIES as i64),
        target: at(0),
    });
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(10), RULE)
            .is_none()
    );
}

#[test]
fn calendar_copies_and_unordered_pairs_preserve_the_strict_remainder() {
    let mut store = store();
    let p = position();
    store
        .record(
            "case",
            p,
            p,
            "/items/*/t",
            "/items/*/t",
            &json!(10),
            &json!(10),
        )
        .unwrap();
    store
        .record(
            "case",
            p,
            p,
            "/items/*/t",
            "/items/*/t",
            &json!(11),
            &json!(11),
        )
        .unwrap();
    let proofs = [
        store
            .proof_for_source("case", p, p, "/items/*/t", "/items/*/t", &json!(10), RULE)
            .unwrap()
            .at("/items/0/t", "/items/*/t"),
        store
            .proof_for_source("case", p, p, "/items/*/t", "/items/*/t", &json!(11), RULE)
            .unwrap()
            .at("/items/1/t", "/items/*/t"),
    ];
    let time = contract(
        "unix_seconds",
        Some("schema.00000000000000000000000000000000"),
    );
    let unordered = FieldContract::Unordered;
    let fields = [
        Field {
            rule_id: RULE,
            pointer: "/items",
            contract: &unordered,
        },
        Field {
            rule_id: RULE,
            pointer: "/items/*/t",
            contract: &time,
        },
    ];
    let source = json!({"items":[{"id":1,"t":10},{"id":2,"t":11}]});
    assert!(
        json::compare_with_time_copies(
            &source,
            &json!({"items":[{"id":2,"t":11},{"id":1,"t":10}]}),
            &fields,
            clocks(),
            &proofs
        )
        .passed()
    );
    assert!(
        !json::compare_with_time_copies(
            &source,
            &json!({"items":[{"id":2,"t":10},{"id":1,"t":11}]}),
            &fields,
            clocks(),
            &proofs
        )
        .passed()
    );
    store
        .record(
            "case",
            p,
            p,
            "/date",
            "/date",
            &json!("2025-01-01"),
            &json!("2025-01-01"),
        )
        .unwrap();
    let proof = store
        .proof_for_source("case", p, p, "/date", "/date", &json!("2025-01-01"), RULE)
        .unwrap();
    let date:FieldContract=serde_json::from_value(json!({"kind":"time","format":"calendar_date","relation":"preserve_offset","utc_offset":"+08:00"})).unwrap();
    let fields = [Field {
        rule_id: RULE,
        pointer: "/date",
        contract: &date,
    }];
    let value = json!({"date":"2025-01-01"});
    assert!(
        json::compare_with_time_copies(&value, &value, &fields, AnchorClocks::default(), &[proof])
            .passed()
    );
}

#[test]
fn copied_schema_fields_keep_declared_clock_relationships() {
    let mut store = store();
    let p = position();
    store
        .record("case", p, p, "/history", "/history", &json!(10), &json!(20))
        .unwrap();
    let proof = store
        .proof_for_source("case", p, p, "/history", "/history", &json!(10), RULE)
        .unwrap();
    let shared = contract("unix_seconds", Some("same-clock"));
    let independent = contract("unix_seconds", Some("new-clock"));
    let mut fields = [
        Field {
            rule_id: RULE,
            pointer: "/history",
            contract: &shared,
        },
        Field {
            rule_id: RULE,
            pointer: "/fresh",
            contract: &shared,
        },
    ];
    let source = json!({"history":10,"fresh":1010});
    let target = json!({"history":20,"fresh":2010});
    assert!(
        !json::compare_with_time_copies(
            &source,
            &target,
            &fields,
            clocks(),
            std::slice::from_ref(&proof)
        )
        .passed()
    );
    fields[1].contract = &independent;
    assert!(json::compare_with_time_copies(&source, &target, &fields, clocks(), &[proof]).passed());
}

#[test]
fn provenance_capacity_fails_closed_and_case_reset_reclaims_it() {
    let mut store = store();
    let p = position();
    for value in 0..MAX_CASE_COPIES {
        store
            .record("case", p, p, "/t", "/t", &json!(value), &json!(value))
            .unwrap();
    }
    assert!(
        store
            .record(
                "case",
                p,
                p,
                "/t",
                "/t",
                &json!(MAX_CASE_COPIES),
                &json!(MAX_CASE_COPIES)
            )
            .is_err()
    );
    store.begin_case("case");
    store
        .record(
            "case",
            p,
            p,
            "/t",
            "/t",
            &json!(MAX_CASE_COPIES),
            &json!(MAX_CASE_COPIES),
        )
        .unwrap();
    assert_eq!(store.total, 1);
}

#[test]
fn typed_copies_preserve_each_source_position_representation_and_numeric_category() {
    let p = position();
    for (format, source, delivered, write_source, write_target) in [
        (
            "sql_datetime",
            "2025-01-01 00:00:00.000",
            "2025-01-01 00:00:00",
            "2025-01-01 00:00:00",
            "2025-01-01 00:00:00.000000",
        ),
        (
            "iso8601_naive",
            "2025-01-01T00:00:00.123000",
            "2025-01-01T00:00:00.123",
            "2025-01-01T00:00:00.123",
            "2025-01-01T00:00:00.123000",
        ),
    ] {
        let field = contract(format, None);
        let time = field.time().unwrap();
        let mut store = store();
        assert!(
            TimeCopyRecord::new_time(&time, p, p, "/t", "/t", &json!(source), &json!(delivered))
                .is_err()
        );
        let record =
            TimeCopyRecord::new_time(&time, p, p, "/t", "/t", &json!(source), &json!(source))
                .unwrap();
        store.record_batch("case", vec![record]).unwrap();
        let proof = store
            .proof_for_source_time(&time, "case", p, p, "/t", "/t", &json!(write_source), RULE)
            .unwrap();
        let fields = [Field {
            rule_id: RULE,
            pointer: "/t",
            contract: &field,
        }];
        assert!(
            json::compare_with_time_copies(
                &json!({"t":write_source}),
                &json!({"t":write_source}),
                &fields,
                clocks(),
                std::slice::from_ref(&proof)
            )
            .passed()
        );
        assert!(
            !json::compare_with_time_copies(
                &json!({"t":write_source}),
                &json!({"t":write_target}),
                &fields,
                clocks(),
                &[proof]
            )
            .passed()
        );
    }
    let time = contract("unix_seconds", None).time().unwrap();
    assert!(TimeCopyRecord::new_time(&time, p, p, "/t", "/t", &json!(10), &json!(10.0)).is_err());
}

#[test]
fn rejected_batch_never_publishes_partial_values_or_ambiguity() {
    let p = position();
    let mut store = store();
    let records = (0..MAX_CASE_COPIES - 1)
        .map(|value| TimeCopyRecord::new(p, p, "/t", "/t", &json!(value), &json!(value)).unwrap())
        .collect();
    store.record_batch("case", records).unwrap();
    let rejected = vec![
        TimeCopyRecord::new(p, p, "/t", "/t", &json!(0), &json!(100)).unwrap(),
        TimeCopyRecord::new(p, p, "/t", "/t", &json!(MAX_CASE_COPIES), &json!(0)).unwrap(),
        TimeCopyRecord::new(p, p, "/t", "/t", &json!(MAX_CASE_COPIES + 1), &json!(0)).unwrap(),
    ];
    assert!(store.record_batch("case", rejected).is_err());
    assert!(
        store
            .proof("case", p, p, "/t", "/t", &json!(0), &json!(0), RULE)
            .is_some()
    );
    assert!(
        store
            .proof_for_source("case", p, p, "/t", "/t", &json!(MAX_CASE_COPIES), RULE)
            .is_none()
    );
    assert_eq!(store.total, MAX_CASE_COPIES - 1);
}
