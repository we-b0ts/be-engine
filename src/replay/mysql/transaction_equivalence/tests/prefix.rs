use super::*;

fn equivalent_prefix_fixture() -> (Registry, Vec<ReplayExchange>) {
    let fixture = records();
    let mut locking_first = fixture[1].clone();
    locking_first["query_sequence"] = json!(1);
    let mut lock = locking_first.clone();
    lock["query_sequence"] = json!(2);
    lock["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
    lock["server_status_before"] = json!(1);
    let mut locking_end = fixture[3].clone();
    locking_end["query_sequence"] = json!(3);
    let ordinary = Uuid::from_u128(2);
    let mut ordinary_first = locking_first.clone();
    ordinary_first["connection_id"] = json!(ordinary);
    let mut ordinary_read = lock.clone();
    ordinary_read["connection_id"] = json!(ordinary);
    ordinary_read["sql"] = json!("SELECT id FROM users WHERE id=2");
    let mut ordinary_end = locking_end.clone();
    ordinary_end["connection_id"] = json!(ordinary);
    registry_with_exchanges(&[
        locking_first,
        lock,
        locking_end,
        ordinary_first,
        ordinary_read,
        ordinary_end,
    ])
}

fn deliver(
    registry: &mut Registry,
    exchanges: &[ReplayExchange],
    witness: &mut Witness,
    index: usize,
    before: u16,
    after: u16,
) -> Observation {
    let record = &exchanges[index].record;
    let confirmed = registry.prefixes.confirmed(index, &record.response);
    if let Some(trace) = witness.active.as_mut()
        && let Some(&(requirement, transaction)) = registry.members.get(&index)
        && let [first, effect, _] = registry.requirements[requirement].transactions[transaction]
            .members
            .as_slice()
        && *effect == index
        && registry.prefixes.covers(*first, trace.neutral_first)
    {
        trace.prefix_equivalent = true;
    }
    registry.observe_delivery_with_prefix(
        witness,
        Delivery {
            command: "COM_QUERY",
            params: None,
            sql: record.sql.as_deref().unwrap(),
            index: Some(index),
            successful: true,
            before,
            after,
        },
        confirmed,
        |_| true,
    )
}

#[test]
fn indistinguishable_first_reads_keep_the_locking_transaction_required() {
    let (mut registry, exchanges) = equivalent_prefix_fixture();
    let prefix = |index: usize, registry: &Registry| {
        registry
            .prefixes
            .confirmed(index, &exchanges[index].record.response)
    };
    let mut different_response = exchanges[0].record.response.clone();
    different_response.rows.clear();
    assert!(
        registry
            .prefixes
            .confirmed(0, &different_response)
            .is_none()
    );
    assert!(prefix(0, &registry).is_some());
    assert_eq!(prefix(0, &registry), prefix(3, &registry));
    assert!(
        registry
            .prefixes
            .group_in_window(0, |_| Some((1, 0)))
            .is_some()
    );
    assert!(
        registry
            .prefixes
            .group_in_window(0, |index| Some((1, usize::from(index != 0))))
            .is_none()
    );

    let mut projection = Witness::default();
    for (index, before, after) in [(0, 0, 1), (4, 1, 1), (5, 1, 0)] {
        let result = deliver(
            &mut registry,
            &exchanges,
            &mut projection,
            index,
            before,
            after,
        );
        assert!(result.violation.is_none());
    }

    let mut catalog = Witness::default();
    assert!(
        deliver(&mut registry, &exchanges, &mut catalog, 3, 0, 1)
            .violation
            .is_none()
    );
    assert!(
        deliver(&mut registry, &exchanges, &mut catalog, 1, 1, 1)
            .violation
            .is_none()
    );
    assert_eq!(registry.preferred_end(&catalog, "COMMIT"), Some(2));
    assert!(registry.requires_witness(2));
    let result = registry.observe_delivery(
        &mut catalog,
        Delivery {
            command: "COM_QUERY",
            params: None,
            sql: "COMMIT",
            index: Some(2),
            successful: true,
            before: 1,
            after: 0,
        },
        |_| true,
    );
    assert!(result.violation.is_none());
    assert!(!registry.requires_witness(2));
}

#[test]
fn equivalent_prefix_cannot_replace_the_lock_or_prove_a_different_socket() {
    for split_connections in [false, true] {
        let (mut registry, exchanges) = equivalent_prefix_fixture();
        let mut reader = Witness::default();
        assert!(
            deliver(&mut registry, &exchanges, &mut reader, 3, 0, 1)
                .violation
                .is_none()
        );
        let mut other = Witness::default();
        let end_socket = if split_connections {
            registry.observe_delivery(
                &mut other,
                Delivery {
                    command: "COM_QUERY",
                    params: None,
                    sql: "BEGIN",
                    index: None,
                    successful: true,
                    before: 2,
                    after: 3,
                },
                |_| true,
            );
            assert!(
                deliver(&mut registry, &exchanges, &mut other, 1, 1, 1)
                    .violation
                    .is_none()
            );
            &mut other
        } else {
            &mut reader
        };
        assert_eq!(registry.preferred_end(end_socket, "COMMIT"), None);
        assert!(
            deliver(&mut registry, &exchanges, end_socket, 2, 1, 0)
                .violation
                .is_some()
        );
        assert!(registry.requires_witness(2));
    }
}
