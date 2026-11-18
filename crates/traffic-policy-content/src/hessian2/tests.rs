use std::collections::BTreeMap;

use motan_hessian2::{ClassSchema, Encoder, Limits, to_vec};

use super::*;

fn body(payload: Vec<u8>) -> Vec<u8> {
    let mut body = vec![3];
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend(payload);
    body
}

#[test]
fn recognizes_one_complete_hessian_value_and_rejects_trailing_bytes() {
    let encoded = to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap();
    assert!(is_hessian2_body(&body(encoded.clone())));
    let mut trailing = encoded;
    trailing.push(b'N');
    assert!(!is_hessian2_body(&body(trailing)));
}

#[test]
fn discovers_and_applies_root_list_order() {
    let expected = body(to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap());
    let actual = body(to_vec(&vec!["beta", "alpha"], Limits::default()).unwrap());

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();

    assert_eq!(discovery.unordered_paths, vec![Hessian2ValuePath(vec![])]);
    assert!(discovery.order_only);
    let rule = Hessian2UnorderedPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.members".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &actual, &[rule], &[]).unwrap());
}

#[test]
fn unordered_list_preserves_duplicate_multiplicity() {
    let expected = body(to_vec(&vec![1_i32, 1, 2], Limits::default()).unwrap());
    let actual = body(to_vec(&vec![2_i32, 1, 2], Limits::default()).unwrap());
    let rule = Hessian2UnorderedPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.members".to_string(),
        source_evidence: "test source contract".to_string(),
    };

    assert!(!compare_hessian2(&expected, &actual, &[rule], &[]).unwrap());
}

#[test]
fn missing_path_is_a_no_op_but_a_non_list_terminal_is_rejected() {
    let expected = body(to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap());
    let missing = Hessian2UnorderedPath {
        value_path: Hessian2ValuePath(vec!["missing".to_string()]),
        display_path: "response.missing".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &expected, std::slice::from_ref(&missing), &[]).unwrap());

    let scalar = Hessian2UnorderedPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.value".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    let scalar_body = body(to_vec(&42_i32, Limits::default()).unwrap());
    assert!(compare_hessian2(&scalar_body, &scalar_body, &[scalar], &[]).is_err());
}

#[test]
fn discovers_and_applies_nested_lists_through_map_keys_and_wildcards() {
    let collection = |groups: &[&[&str]]| {
        BTreeMap::from([(
            "groups".to_string(),
            groups
                .iter()
                .map(|names| {
                    BTreeMap::from([(
                        "names".to_string(),
                        names.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    )])
                })
                .collect::<Vec<_>>(),
        )])
    };
    let expected = body(
        to_vec(
            &collection(&[&["alice", "bob"], &["carol", "dave"]]),
            Limits::default(),
        )
        .unwrap(),
    );
    let actual = body(
        to_vec(
            &collection(&[&["bob", "alice"], &["dave", "carol"]]),
            Limits::default(),
        )
        .unwrap(),
    );

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();

    let value_path = Hessian2ValuePath(vec![
        "groups".to_string(),
        "*".to_string(),
        "names".to_string(),
    ]);
    assert_eq!(discovery.unordered_paths, vec![value_path.clone()]);
    assert!(discovery.order_only);
    assert!(
        compare_hessian2(
            &expected,
            &actual,
            &[Hessian2UnorderedPath {
                value_path,
                display_path: "rule_collection.groups[].names".to_string(),
                source_evidence: "test source contract".to_string(),
            }],
            &[],
        )
        .unwrap()
    );
}

#[test]
fn applies_a_list_path_through_an_object_field() {
    fn response(names: &[&str]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut encoder = Encoder::new(&mut payload, Limits::default());
        encoder
            .begin_object(ClassSchema::new("example.Response", &["names"]))
            .unwrap();
        encoder.encode_value(&names.to_vec()).unwrap();
        encoder.end_object();
        body(payload)
    }

    let expected = response(&["alice", "bob"]);
    let actual = response(&["bob", "alice"]);
    let rule = Hessian2UnorderedPath {
        value_path: Hessian2ValuePath(vec!["names".to_string()]),
        display_path: "response.names".to_string(),
        source_evidence: "test source contract".to_string(),
    };

    assert!(compare_hessian2(&expected, &actual, &[rule], &[]).unwrap());
}

/// Compact Hessian2 string, valid for the ASCII names used by these fixtures.
fn string(value: &str) -> Vec<u8> {
    assert!(value.len() < 32 && value.is_ascii());
    let mut encoded = vec![u8::try_from(value.len()).unwrap()];
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

/// Compact Hessian2 integer, valid for `0..=47`.
fn int(value: u8) -> Vec<u8> {
    assert!(value <= 47);
    vec![0x90 + value]
}

fn untyped_fixed_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut encoded = if items.len() <= 7 {
        vec![0x78 + u8::try_from(items.len()).unwrap()]
    } else {
        [vec![b'X'], int(u8::try_from(items.len()).unwrap())].concat()
    };
    for item in items {
        encoded.extend_from_slice(item);
    }
    encoded
}

fn untyped_map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut encoded = vec![b'H'];
    for (key, value) in entries {
        encoded.extend(string(key));
        encoded.extend_from_slice(value);
    }
    encoded.push(b'Z');
    encoded
}

/// Fixed-length typed list, the form Java writes for more than seven elements.
fn typed_fixed_list(type_name: &str, items: &[Vec<u8>]) -> Vec<u8> {
    let mut encoded = vec![b'V'];
    encoded.extend(string(type_name));
    encoded.extend(int(u8::try_from(items.len()).unwrap()));
    for item in items {
        encoded.extend_from_slice(item);
    }
    encoded
}

/// One single-field object per class definition, so the last instance uses the
/// compact class-index tag `0x6c`.
fn thirteen_class_body(last_field: Vec<u8>) -> Vec<u8> {
    let items = (0..13)
        .map(|index| {
            let mut encoded = vec![b'C'];
            encoded.extend(string(&format!("example.Node{index}")));
            encoded.extend(int(1));
            encoded.extend(string("value"));
            encoded.push(0x60 + index);
            if index == 12 {
                encoded.extend_from_slice(&last_field);
            } else {
                encoded.extend(untyped_fixed_list(&[string("shared")]));
            }
            encoded
        })
        .collect::<Vec<_>>();
    untyped_fixed_list(&items)
}

#[test]
fn wildcard_unordered_path_skips_non_list_siblings_and_keeps_them_exact() {
    let response = |names: &[&str], scalar: u8| {
        untyped_map(&[(
            "groups",
            untyped_fixed_list(&[
                untyped_map(&[(
                    "candidates",
                    untyped_fixed_list(&names.iter().copied().map(string).collect::<Vec<_>>()),
                )]),
                untyped_map(&[("candidates", int(scalar))]),
            ]),
        )])
    };
    let expected = response(&["alice", "bob"], 7);
    let actual = response(&["bob", "alice"], 7);

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();
    let value_path = Hessian2ValuePath(vec![
        "groups".to_string(),
        "*".to_string(),
        "candidates".to_string(),
    ]);
    assert_eq!(discovery.unordered_paths, vec![value_path.clone()]);
    assert!(discovery.order_only);
    let rule = Hessian2UnorderedPath {
        value_path,
        display_path: "response.groups[].candidates".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &actual, std::slice::from_ref(&rule), &[]).unwrap());
    assert!(!compare_hessian2(&expected, &response(&["bob", "alice"], 8), &[rule], &[]).unwrap());
}

#[test]
fn wildcard_joined_string_path_skips_non_string_siblings_and_keeps_them_exact() {
    let response = |names: &str, scalar: u8| {
        untyped_map(&[(
            "groups",
            untyped_fixed_list(&[
                untyped_map(&[("candidates", string(names))]),
                untyped_map(&[("candidates", int(scalar))]),
            ]),
        )])
    };
    let expected = response("alice,bob", 7);
    let actual = response("bob,alice", 7);

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();
    let value_path = Hessian2ValuePath(vec![
        "groups".to_string(),
        "*".to_string(),
        "candidates".to_string(),
    ]);
    assert_eq!(
        discovery.unordered_joined_string_paths,
        vec![(value_path.clone(), ",".to_string())]
    );
    assert!(discovery.candidates_explain_all_differences);
    let rule = Hessian2JoinedStringPath {
        value_path,
        display_path: "response.groups[].candidates".to_string(),
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &actual, &[], std::slice::from_ref(&rule)).unwrap());
    assert!(!compare_hessian2(&expected, &response("bob,alice", 8), &[], &[rule]).unwrap());
}

#[test]
fn accepts_bare_and_enveloped_hessian2_bodies() {
    let payload = to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap();

    assert!(is_hessian2_body(&payload));
    assert!(is_hessian2_body(&body(payload)));
    assert!(!is_hessian2_body(b"NN"));
}

#[test]
fn discovers_and_applies_list_order_in_a_bare_body() {
    let expected = to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap();
    let actual = to_vec(&vec!["beta", "alpha"], Limits::default()).unwrap();

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();

    assert_eq!(discovery.envelope, BodyEnvelope::Raw);
    assert_eq!(discovery.unordered_paths, vec![Hessian2ValuePath(vec![])]);
    assert!(discovery.order_only);
    let rule = Hessian2UnorderedPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.names".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &actual, &[rule], &[]).unwrap());
}

#[test]
fn rejects_compared_bodies_that_change_envelope() {
    let payload = to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap();

    let error = discover_hessian2_order(&body(payload.clone()), &payload)
        .err()
        .unwrap();

    assert!(
        error
            .to_string()
            .contains("different envelopes: source-before simple_byte_array and candidate raw"),
        "{error}"
    );
}

#[test]
fn discovers_order_inside_a_fixed_length_typed_list() {
    let names = |names: &[&str]| {
        typed_fixed_list(
            "[string",
            &names.iter().copied().map(string).collect::<Vec<_>>(),
        )
    };

    let discovery =
        discover_hessian2_order(&names(&["alice", "bob"]), &names(&["bob", "alice"])).unwrap();

    assert_eq!(discovery.unordered_paths, vec![Hessian2ValuePath(vec![])]);
    assert!(discovery.order_only);
}

#[test]
fn discovers_order_under_an_object_with_a_high_class_index() {
    let names = |names: &[&str]| {
        thirteen_class_body(untyped_fixed_list(
            &names.iter().copied().map(string).collect::<Vec<_>>(),
        ))
    };
    let expected = names(&["alice", "bob"]);
    let actual = names(&["bob", "alice"]);

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();

    let value_path = Hessian2ValuePath(vec!["*".to_string(), "value".to_string()]);
    assert_eq!(discovery.unordered_paths, vec![value_path.clone()]);
    assert!(discovery.order_only);
    assert!(
        compare_hessian2(
            &expected,
            &actual,
            &[Hessian2UnorderedPath {
                value_path,
                display_path: "nodes[].value".to_string(),
                source_evidence: "test source contract".to_string(),
            }],
            &[],
        )
        .unwrap()
    );
}

#[test]
fn joined_string_matches_when_elements_differ_only_by_order() {
    let expected = body(to_vec(&"alice,bob,carol", Limits::default()).unwrap());
    let actual = body(to_vec(&"carol,alice,bob", Limits::default()).unwrap());

    let rule = Hessian2JoinedStringPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.white_list".to_string(),
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &actual, &[], &[rule]).unwrap());
}

#[test]
fn joined_string_preserves_duplicate_multiplicity() {
    let expected = body(to_vec(&"alice,alice,bob", Limits::default()).unwrap());
    let actual = body(to_vec(&"alice,bob,bob", Limits::default()).unwrap());
    let rule = Hessian2JoinedStringPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.white_list".to_string(),
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(!compare_hessian2(&expected, &actual, &[], &[rule]).unwrap());
}

#[test]
fn joined_string_missing_path_is_a_no_op_but_a_non_string_terminal_is_rejected() {
    let list_body = body(to_vec(&vec!["alpha", "beta"], Limits::default()).unwrap());
    let missing = Hessian2JoinedStringPath {
        value_path: Hessian2ValuePath(vec!["missing".to_string()]),
        display_path: "response.missing".to_string(),
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&list_body, &list_body, &[], std::slice::from_ref(&missing)).unwrap());

    let present_non_string = Hessian2JoinedStringPath {
        value_path: Hessian2ValuePath(vec![]),
        display_path: "response.value".to_string(),
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(
        compare_hessian2(
            &list_body,
            &list_body,
            &[],
            std::slice::from_ref(&present_non_string)
        )
        .is_err()
    );
}

#[test]
fn joined_string_path_reaches_a_nested_field() {
    fn response(white_list: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut encoder = Encoder::new(&mut payload, Limits::default());
        encoder
            .begin_object(ClassSchema::new("example.Response", &["whiteList"]))
            .unwrap();
        encoder.encode_value(&white_list.to_string()).unwrap();
        encoder.end_object();
        body(payload)
    }

    let expected = response("alice,bob,carol");
    let actual = response("carol,bob,alice");
    let rule = Hessian2JoinedStringPath {
        value_path: Hessian2ValuePath(vec!["whiteList".to_string()]),
        display_path: "response.white_list".to_string(),
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    assert!(compare_hessian2(&expected, &actual, &[], &[rule]).unwrap());
}

#[test]
fn discovers_a_joined_string_candidate_with_the_matching_separator() {
    let expected = body(to_vec(&"alice,bob", Limits::default()).unwrap());
    let actual = body(to_vec(&"bob,alice", Limits::default()).unwrap());

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();

    assert_eq!(
        discovery.unordered_joined_string_paths,
        vec![(Hessian2ValuePath(vec![]), ",".to_string())]
    );
    // The reordered joined string is not a list, so no list candidate appears.
    assert!(discovery.unordered_paths.is_empty());
}

#[test]
fn joined_string_discovery_skips_fields_that_are_not_reordered_sets() {
    let expected = body(to_vec(&"alice,bob", Limits::default()).unwrap());
    let actual = body(to_vec(&"alice,carol", Limits::default()).unwrap());

    let discovery = discover_hessian2_order(&expected, &actual).unwrap();

    assert!(discovery.unordered_joined_string_paths.is_empty());
    assert!(discovery.unordered_paths.is_empty());
}

fn compare_hessian2(
    expected: &[u8],
    actual: &[u8],
    unordered_paths: &[Hessian2UnorderedPath],
    joined_string_paths: &[Hessian2JoinedStringPath],
) -> Result<bool> {
    super::compare_hessian2(
        traffic_extensions::policies(),
        expected,
        actual,
        unordered_paths,
        joined_string_paths,
    )
}

fn discover_hessian2_order(expected: &[u8], actual: &[u8]) -> Result<Hessian2OrderDiscovery> {
    super::discover_hessian2_order(traffic_extensions::policies(), expected, actual)
}
