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

#[test]
fn reservation_consumes_only_the_confirmed_source_occurrence() {
    let window = |_: &ReplayExchange, _: &ReplayExchange| Some(11);
    for seconds in [[1, 4], [4, 1]] {
        let (mut registry, mut exchanges) = equivalent_prefix_fixture();
        let response = exchanges[0].record.response.clone();
        let first = registry
            .prefixes
            .reserve(0, &response, &exchanges, window, true)
            .unwrap()
            .unwrap();
        assert!(first.1.publish_wire());
        let second = registry
            .prefixes
            .reserve(0, &response, &exchanges, window, true)
            .unwrap()
            .unwrap();
        assert!(second.1.publish_wire());
        assert!(
            registry
                .prefixes
                .reserve(0, &response, &exchanges, window, true)
                .is_err()
        );
        assert!(exchanges[0].status.is_available());
        assert!(exchanges[3].status.is_available());
        for ((reservation, ticket), next) in [first, second].into_iter().zip(seconds) {
            assert!(
                registry
                    .prefixes
                    .resolve(reservation, 2, &exchanges, window)
                    .is_none()
            );
            assert!(
                registry
                    .prefixes
                    .resolve(reservation, next, &exchanges, |_, _| Some(12))
                    .is_none()
            );
            let selected = registry
                .prefixes
                .resolve(reservation, next, &exchanges, window)
                .unwrap();
            assert_eq!(selected, next - 1);
            assert!(registry.prefixes.confirm(reservation, &ticket));
            assert!(!registry.prefixes.confirm(reservation, &ticket));
            exchanges[selected].status = ReplayExchangeStatus::Consumed;
        }
        assert!(registry.requires_witness(2));
    }
}

#[test]
fn reservation_requires_matching_wire_response_and_an_uninterrupted_window() {
    let (mut registry, exchanges) = equivalent_prefix_fixture();
    let response = &exchanges[0].record.response;
    assert!(
        registry
            .prefixes
            .reserve(0, response, &exchanges, |_, _| None, true)
            .unwrap()
            .is_none()
    );
    let mut different = response.clone();
    different.rows.clear();
    assert!(
        registry
            .prefixes
            .reserve(0, &different, &exchanges, |_, _| Some(11), true)
            .unwrap()
            .is_none()
    );
    assert!(
        registry
            .prefixes
            .reserve(0, response, &exchanges, |_, _| Some(11), false)
            .unwrap()
            .is_none()
    );
}
