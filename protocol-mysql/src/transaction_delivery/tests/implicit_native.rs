//! Native implicit transactions require real connection-local status evidence.
use super::*;

fn complete_source() -> Vec<Value> {
    let mut values = records();
    values.truncate(4);
    for (index, value) in values.iter_mut().enumerate() {
        value["query_sequence"] = json!(index + 1);
    }
    values
}

fn deliver(
    registry: &mut Registry,
    witness: &mut Witness,
    index: Option<usize>,
    successful: bool,
    before: u16,
    after: u16,
) -> Observation {
    let sql = match index {
        Some(0) => "SET AUTOCOMMIT=0",
        Some(1) => "SELECT id FROM users WHERE id=1",
        Some(2) => "UPDATE users SET active=1 WHERE id=1",
        Some(3) => "COMMIT",
        _ => "SELECT 1",
    };
    registry.observe_delivery(
        witness,
        Delivery {
            command: "COM_QUERY",
            params: None,
            sql,
            index,
            successful,
            before,
            after,
        },
        |_| false,
    )
}

#[test]
fn implicit_native_transaction_keeps_real_commit_mandatory_until_delivery() {
    let mut registry = registry(&complete_source());
    let mut witness = Witness::default();
    deliver(&mut registry, &mut witness, Some(0), true, 2, 0);
    deliver(&mut registry, &mut witness, Some(1), true, 0, 1);
    assert!(witness.active.as_ref().unwrap().members.is_empty());
    deliver(&mut registry, &mut witness, Some(2), true, 1, 1);
    assert_eq!(registry.preferred_end(&witness, "COMMIT"), Some(3));
    assert!(registry.requires_witness(3));
    assert!(!registry.covered_by(3, witness.connection()));
    deliver(&mut registry, &mut witness, Some(3), true, 1, 0);
    assert!(registry.covered_by(3, witness.connection()));
    assert!(!registry.requires_witness(3));
}

#[test]
fn missing_or_unsafe_start_evidence_cannot_create_an_implicit_trace() {
    for (index, successful, before, after) in [
        (None, true, 0, 1),
        (Some(0), true, 0, 1),
        (Some(1), false, 0, 1),
        (Some(1), true, 0, 0),
        (Some(1), true, 1, 1),
        (Some(1), true, 2, 3),
        (Some(1), true, 0, 0x2001),
        (Some(3), true, 0, 1),
    ] {
        let mut registry = registry(&complete_source());
        let mut witness = Witness::default();
        deliver(
            &mut registry,
            &mut witness,
            index,
            successful,
            before,
            after,
        );
        assert!(witness.active.is_none());
        assert!(registry.requires_witness(3));
        assert!(!registry.covered_by(3, witness.connection()));
    }
}

#[test]
fn an_implicit_trace_cannot_supply_another_sockets_end_or_a_failed_end() {
    for failed in [false, true] {
        let mut registry = registry(&complete_source());
        let mut witness = Witness::default();
        deliver(&mut registry, &mut witness, Some(1), true, 0, 1);
        deliver(&mut registry, &mut witness, Some(2), true, 1, 1);
        let mut other = Witness::default();
        let ending = if failed { &mut witness } else { &mut other };
        deliver(&mut registry, ending, Some(3), !failed, 1, 0);
        assert!(registry.requires_witness(3));
        assert!(!registry.covered_by(3, witness.connection()));
    }
}
