use super::*;

fn values() -> Vec<Value> {
    let mut values = records()[1..4].to_vec();
    values[0]["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
    values[1]["sql"] = json!("INSERT INTO users (id) VALUES (1)");
    values[1]["response"] = json!({"status":"error","error_code":1062});
    values[2]["sql"] = json!("ROLLBACK");
    values[2]["server_status_before"] = Value::Null;
    values
}

fn deliver_prefix(r: &mut Registry, witness: &mut Witness) {
    r.observe(witness, "BEGIN", None, true);
    r.observe(
        witness,
        "SELECT id FROM users WHERE id=1 FOR UPDATE",
        Some(0),
        true,
    );
    r.observe(witness, "INSERT INTO users (id) VALUES (1)", Some(1), false);
}

#[test]
fn missing_err_status_requires_the_full_native_transaction_and_real_end() {
    let mut r = registry(&values());
    let group = &r.requirements[0].transactions[0];
    assert!(group.strict);
    assert!(!group.autocommit_eligible());
    assert_eq!(group.members, [0, 1, 2]);
    assert_eq!(group.write_count, 1);
    assert!(group.witness.is_none());
    assert!(r.requires_witness(2));
    let mut witness = Witness::default();
    deliver_prefix(&mut r, &mut witness);
    assert_eq!(r.preferred_end(&witness, "ROLLBACK"), Some(2));
    assert_eq!(r.preferred_end(&witness, "COMMIT"), None);
    assert!(r.requirements[0].transactions[0].witness.is_none());
    r.observe(&mut witness, "ROLLBACK", Some(2), true);
    assert!(r.covered_by(2, witness.connection()));
}

#[test]
fn missing_err_status_never_permits_partial_split_unscoped_or_reordered_delivery() {
    for mode in [
        "prefix_missing",
        "split",
        "autocommit",
        "reordered",
        "extra",
        "commit",
        "failed_end",
    ] {
        let mut r = registry(&values());
        let mut first = Witness::default();
        let mut second = Witness::default();
        if mode != "autocommit" {
            r.observe(&mut first, "BEGIN", None, true);
        }
        if mode != "prefix_missing" && mode != "reordered" {
            r.observe(&mut first, "SELECT id FROM users FOR UPDATE", Some(0), true);
        }
        let target = if mode == "split" {
            &mut second
        } else {
            &mut first
        };
        r.observe(target, "INSERT INTO users (id) VALUES (1)", Some(1), false);
        if mode == "reordered" {
            r.observe(target, "SELECT id FROM users FOR UPDATE", Some(0), true);
        }
        if mode == "extra" {
            r.observe(target, "SELECT 1", None, true);
        }
        assert_eq!(
            r.preferred_end(target, "ROLLBACK"),
            matches!(mode, "commit" | "failed_end").then_some(2),
            "{mode}"
        );
        r.observe(
            target,
            if mode == "commit" {
                "COMMIT"
            } else {
                "ROLLBACK"
            },
            Some(2),
            mode != "failed_end",
        );
        assert!(
            r.requirements[0].transactions[0].witness.is_none(),
            "{mode}"
        );
        assert!(r.requires_witness(2), "{mode}");
    }
}

#[test]
fn an_unknown_error_boundary_without_a_complete_source_envelope_stays_rejected() {
    let original = values();
    let mut variants = Vec::new();
    for (index, field, value) in [
        (0, "server_status_before", Value::Null),
        (0, "server_status_before", json!(1)),
        (0, "query_sequence", json!(4)),
        (0, "database", json!("foreign")),
        (0, "connection_id", json!(Uuid::from_u128(9))),
        (1, "server_status_before", Value::Null),
        (1, "server_status_before", json!(0)),
        (1, "sql", json!("CALL mutate()")),
        (
            1,
            "sql",
            json!("INSERT INTO users (id) VALUES (GET_LOCK('x',1))"),
        ),
        (
            1,
            "sql",
            json!("INSERT INTO users (id) VALUES (1); UPDATE users SET id=2"),
        ),
        (1, "parse_warnings", json!(["incomplete"])),
        (2, "query_sequence", json!(8)),
        (2, "query_sequence", Value::Null),
        (2, "database", json!("foreign")),
        (2, "connection_id", json!(Uuid::from_u128(9))),
        (2, "sql", json!("COMMIT")),
        (2, "sql", json!("ROLLBACK AND CHAIN")),
        (2, "server_status_before", json!(1)),
    ] {
        let mut changed = original.clone();
        changed[index][field] = value;
        variants.push(changed);
    }
    for (index, field, value) in [
        (0, "server_status", Value::Null),
        (0, "server_status", json!(0)),
        (1, "error_code", Value::Null),
        (1, "rows_truncated", json!(true)),
        (1, "affected_rows", json!(0)),
        (2, "server_status", Value::Null),
        (2, "server_status", json!(1)),
        (2, "server_status", json!(2)),
        (2, "server_status", json!(8)),
        (2, "status", json!("error")),
    ] {
        let mut changed = original.clone();
        changed[index]["response"][field] = value;
        variants.push(changed);
    }
    let mut duplicated = original.clone();
    duplicated.insert(1, original[0].clone());
    variants.push(duplicated);
    variants.push(original[1..].to_vec());
    variants.push(original[..2].to_vec());
    // An earlier failed statement that reports an inactive status cannot be
    // smuggled into the same Source transaction by starting another read.
    let mut inactive_error = original[1].clone();
    inactive_error["sql"] = json!("UPDATE users SET active=1 WHERE id=1");
    inactive_error["response"]["server_status"] = json!(0);
    let mut restart = original[0].clone();
    restart["query_sequence"] = json!(7);
    let mut restarted = vec![original[0].clone(), inactive_error, restart];
    let mut later = original[1..].to_vec();
    later[0]["query_sequence"] = json!(8);
    later[1]["query_sequence"] = json!(9);
    restarted.extend(later);
    variants.push(restarted);
    for (variant, values) in variants.iter().enumerate() {
        let r = registry(values);
        assert!(
            r.requirements.iter().all(|r| r.transactions.is_empty()),
            "variant {variant}"
        );
    }
}

#[test]
fn global_read_bridges_never_fill_an_err_rollback_envelope() {
    let mut case = values();
    case[0]["sql"] = json!("SELECT id FROM users WHERE id=1");
    case[1]["query_sequence"] = json!(7);
    case[2]["query_sequence"] = json!(8);
    let mut global = case[0].clone();
    global["query_sequence"] = json!(6);
    global["server_status_before"] = json!(1);
    let plans = scoped_plans(&case, &[global]);
    assert!(plans[0].transactions.is_empty());
    assert_eq!(plans[0].reason, Some("source_status_missing"));
}

#[test]
fn native_failed_dml_envelopes_always_retain_reads_and_the_end() {
    for sql in [
        "INSERT INTO users (id) VALUES (1)",
        "UPDATE users SET active=1 WHERE id=1",
        "DELETE FROM users WHERE id=1",
        "REPLACE INTO users (id) VALUES (1)",
    ] {
        let mut values = values();
        values[1]["sql"] = json!(sql);
        let r = registry(&values);
        let group = &r.requirements[0].transactions[0];
        assert!(group.strict, "{sql}");
        assert_eq!(group.members, [0, 1, 2], "{sql}");
        assert!(!group.autocommit_eligible(), "{sql}");
    }
}

#[test]
fn native_error_envelopes_preserve_explicit_starts_and_later_transactions() {
    let mut first = values();
    let mut begin = records()[3].clone();
    begin["sql"] = json!("BEGIN");
    begin["query_sequence"] = json!(4);
    begin["server_status_before"] = json!(0);
    begin["response"]["server_status"] = json!(1);
    first[0]["server_status_before"] = json!(1);
    first.insert(0, begin);
    let mut second = values();
    for (record, sequence) in second.iter_mut().zip([8, 9, 10]) {
        record["query_sequence"] = json!(sequence);
    }
    first.extend(second);
    let mut r = registry(&first);
    assert_eq!(r.requirements[0].transactions.len(), 2);
    assert!(r.requirements[0].source_reason.is_some()); // strict delivery only
    assert!(r.requirements[0].transactions[0].explicit);
    let mut witness = Witness::default();
    r.observe(&mut witness, "BEGIN", Some(0), true);
    r.observe(
        &mut witness,
        "SELECT id FROM users FOR UPDATE",
        Some(1),
        true,
    );
    r.observe(
        &mut witness,
        "INSERT INTO users (id) VALUES (1)",
        Some(2),
        false,
    );
    assert_eq!(r.preferred_end(&witness, "ROLLBACK"), Some(3));
    r.observe(&mut witness, "ROLLBACK", Some(3), true);
    r.observe(&mut witness, "BEGIN", None, true);
    r.observe(
        &mut witness,
        "SELECT id FROM users FOR UPDATE",
        Some(4),
        true,
    );
    r.observe(
        &mut witness,
        "INSERT INTO users (id) VALUES (1)",
        Some(5),
        false,
    );
    assert_eq!(r.preferred_end(&witness, "ROLLBACK"), Some(6));
    r.observe(&mut witness, "ROLLBACK", Some(6), true);
    assert!(r.covered_by(3, witness.connection()));
    assert!(r.covered_by(6, witness.connection()));
}
