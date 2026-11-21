use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use super::*;

fn endpoint(port: u16) -> Endpoint {
    Endpoint {
        host: "redis.example".to_owned(),
        port,
    }
}

fn value() -> (Bytes, Weak<[u8]>) {
    let owner: Arc<[u8]> = Arc::new([1, 2, 3]);
    let weak = Arc::downgrade(&owner);
    (Bytes::from_owner(owner), weak)
}

fn receipt(now: Instant, index: usize, value: Option<Bytes>) -> Receipt {
    Receipt {
        completed_at: now + Duration::from_millis(index as u64),
        index,
        argument: value.as_ref().map(|_| 1),
        value,
    }
}

#[test]
fn field_key_and_type_invalidations_release_only_covered_values() {
    let endpoint = endpoint(6379);
    let key = Bytes::from_static(b"account");
    let balance = Location::Field(0, key.clone(), Bytes::from_static(b"balance"));
    let opened = Location::Field(0, key.clone(), Bytes::from_static(b"opened"));
    let string = Location::String(0, key.clone());
    let unrelated = Location::String(0, Bytes::from_static(b"alert"));
    let now = Instant::now();
    let mut state = State::default();
    let (balance_value, balance_memory) = value();
    let (opened_value, opened_memory) = value();
    let (string_value, string_memory) = value();
    let (unrelated_value, unrelated_memory) = value();
    state.publish(
        &endpoint,
        true,
        &balance,
        receipt(now, 1, Some(balance_value)),
    );
    state.publish(
        &endpoint,
        true,
        &opened,
        receipt(now, 2, Some(opened_value)),
    );
    state.publish(
        &endpoint,
        true,
        &unrelated,
        receipt(now, 3, Some(unrelated_value)),
    );

    state.publish(&endpoint, true, &balance, receipt(now, 4, None));
    assert!(balance_memory.upgrade().is_none());
    assert!(opened_memory.upgrade().is_some());
    assert_eq!(state.latest(&endpoint, &balance).unwrap().index, 4);

    state.publish(
        &endpoint,
        true,
        &Location::Hash(0, key.clone()),
        receipt(now, 5, None),
    );
    state.publish(
        &endpoint,
        true,
        &string,
        receipt(now, 5, Some(string_value)),
    );
    assert!(opened_memory.upgrade().is_none());
    assert!(string_memory.upgrade().is_some());
    assert_eq!(state.latest(&endpoint, &opened).unwrap().index, 5);

    state.publish(
        &endpoint,
        true,
        &Location::Key(0, key),
        receipt(now, 6, None),
    );
    assert!(string_memory.upgrade().is_none());
    assert!(unrelated_memory.upgrade().is_some());
    assert_eq!(state.latest(&endpoint, &string).unwrap().index, 6);
    assert_eq!(state.latest(&endpoint, &unrelated).unwrap().index, 3);
}

#[test]
fn late_invalidation_preserves_newer_fields_and_delayed_writes_cannot_revive_old_ones() {
    let endpoint = endpoint(6379);
    let key = Bytes::from_static(b"account");
    let old = Location::Field(0, key.clone(), Bytes::from_static(b"old"));
    let new = Location::Field(0, key.clone(), Bytes::from_static(b"new"));
    let now = Instant::now();
    let mut state = State::default();
    let (old_value, old_memory) = value();
    let (delayed_value, delayed_memory) = value();
    let (new_value, new_memory) = value();
    state.publish(&endpoint, true, &old, receipt(now, 1, Some(old_value)));
    state.publish(&endpoint, true, &new, receipt(now, 4, Some(new_value)));

    state.publish(
        &endpoint,
        true,
        &Location::Key(0, key),
        receipt(now, 3, None),
    );
    assert!(old_memory.upgrade().is_none());
    assert_eq!(state.latest(&endpoint, &old).unwrap().index, 3);
    assert!(new_memory.upgrade().is_some());
    assert_eq!(state.latest(&endpoint, &new).unwrap().index, 4);

    state.publish(&endpoint, true, &old, receipt(now, 2, Some(delayed_value)));
    assert!(delayed_memory.upgrade().is_none());
    assert_eq!(state.latest(&endpoint, &old).unwrap().index, 3);
}

#[test]
fn run_fences_free_case_payloads_without_touching_other_databases_or_endpoints() {
    let first = endpoint(6379);
    let second = endpoint(6380);
    let key = Bytes::from_static(b"k");
    let db0 = Location::String(0, key.clone());
    let db1 = Location::String(1, key);
    let now = Instant::now();
    let mut state = State::default();
    let (db0_value, db0_memory) = value();
    let (db1_value, db1_memory) = value();
    let (other_value, other_memory) = value();
    state.publish(&first, true, &db0, receipt(now, 1, Some(db0_value)));
    state.publish(&first, true, &db1, receipt(now, 2, Some(db1_value)));
    state.publish(&second, true, &db0, receipt(now, 3, Some(other_value)));

    state.publish(&first, false, &Location::Database(0), receipt(now, 4, None));
    assert!(db0_memory.upgrade().is_none());
    assert!(db1_memory.upgrade().is_some());
    assert!(other_memory.upgrade().is_some());
    assert_eq!(state.latest(&first, &db0).unwrap().index, 4);

    let (delayed_value, delayed_memory) = value();
    state.publish(&first, true, &db0, receipt(now, 3, Some(delayed_value)));
    assert!(delayed_memory.upgrade().is_none());
    state.publish(&first, false, &Location::Endpoint, receipt(now, 5, None));
    assert!(db1_memory.upgrade().is_none());
    assert!(other_memory.upgrade().is_some());
    state.clear_case();
    assert!(other_memory.upgrade().is_none());
    assert_eq!(state.latest(&first, &db1).unwrap().index, 5);
    assert!(state.latest(&second, &db0).is_none());
}
