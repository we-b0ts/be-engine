use super::*;

fn rule(id: &str, number: u32, kind: &str) -> CompiledRule {
    let yaml = format!(
        r#"id: {id}
surface: api.response
match: {{api: GET /requests}}
slot: body
codec:
  kind: protobuf
  fields:
    /{id}: {{field_path: [{number}], field_type: {kind}}}
contract:
  /{id}: {{kind: duration, unit: seconds}}
proof: {{source: 'clock.py:elapsed', fact: 'Source stores elapsed dependency request seconds'}}
"#
    );
    compile_rule(&serde_yaml::from_str(&yaml).unwrap()).unwrap()
}

#[test]
fn overlapping_pb_group_is_prepared_once_and_order_does_not_change_its_identity() {
    super::super::prepared::clear();
    let left = rule("left", 1, "uint64");
    let right = rule("right", 2, "uint64");
    let ((first, second), compiles) = crate::value_codec::measured_compiles(|| {
        let first = prepared_codec(&[&left, &right]).unwrap();
        let second = prepared_codec(&[&right, &left]).unwrap();
        for _ in 0..16 {
            assert!(Arc::ptr_eq(
                &first,
                &prepared_codec(&[&left, &right]).unwrap()
            ));
        }
        (first, second)
    });
    assert_eq!(compiles, 1);
    assert!(Arc::ptr_eq(&first, &second));
    let clocks = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: chrono::DateTime::from_timestamp(10, 0),
            target: chrono::DateTime::from_timestamp(110, 0),
        },
        ..Default::default()
    };
    assert!(
        compare(
            &[8, 10, 16, 20, 24, 7],
            &[8, 110, 16, 120, 24, 7],
            &[&left, &right],
            clocks
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            &[8, 10, 16, 20, 24, 7],
            &[8, 110, 16, 120, 24, 8],
            &[&left, &right],
            clocks
        )
        .unwrap()
        .passed()
    );
    assert_eq!(
        first
            .decode(&[8, 10, 16, 20, 24, 7])
            .unwrap()
            .encode(&first.decode(&[8, 10, 16, 20, 24, 7]).unwrap().logical, &[])
            .unwrap(),
        [8, 10, 16, 20, 24, 7]
    );
}

#[test]
fn group_cache_never_reuses_another_prepared_type_or_a_conflicting_wire_alias() {
    super::super::prepared::clear();
    let left = rule("left", 1, "uint64");
    let right = rule("right", 2, "uint64");
    let prepared = prepared_codec(&[&left, &right]).unwrap();
    let signed = rule("right", 2, "int64");
    assert!(!Arc::ptr_eq(
        &prepared,
        &prepared_codec(&[&left, &signed]).unwrap()
    ));
    let alias = rule("alias", 1, "uint64");
    assert!(prepared_codec(&[&left, &alias]).is_err());
    assert!(Arc::ptr_eq(
        &prepared,
        &prepared_codec(&[&left, &right]).unwrap()
    ));
}

#[test]
fn prepared_groups_are_bounded_and_eviction_keeps_retained_plans_valid() {
    super::super::prepared::clear();
    let left = rule("left", 1, "uint64");
    let right = rule("right", 2, "uint64");
    let retained = prepared_codec(&[&left, &right]).unwrap();
    for index in 0..70 {
        let next = rule(&format!("right{index}"), 2, "uint64");
        prepared_codec(&[&left, &next]).unwrap();
    }
    let (groups, bytes) = super::super::prepared::occupancy();
    assert_eq!(groups, 64);
    assert!(bytes <= 8 * 1024 * 1024);
    let decoded = retained.decode(&[8, 1, 16, 2]).unwrap();
    assert_eq!(decoded.logical["left"], 1);
    assert_eq!(decoded.logical["right"], 2);
    assert_eq!(
        decoded.encode(&decoded.logical, &[]).unwrap(),
        [8, 1, 16, 2]
    );
}
