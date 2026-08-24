use super::*;
use crate::replay::policy::ProtobufJoinedStringFieldType;

fn bytes_field(number: u32, value: &[u8]) -> Vec<u8> {
    assert!(number < 16 && value.len() < 128);
    let mut field = vec![((number << 3) | 2) as u8, value.len() as u8];
    field.extend_from_slice(value);
    field
}

fn varint_field(number: u32, value: u8) -> Vec<u8> {
    assert!(number < 16 && value < 128);
    vec![(number << 3) as u8, value]
}

fn message(fields: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    fields.into_iter().flatten().collect()
}

fn body(payload: Vec<u8>) -> Vec<u8> {
    let mut body = vec![3];
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend(payload);
    body
}

#[test]
fn discovers_and_applies_nested_repeated_field_order() {
    let expected_group = message([bytes_field(3, b"alice"), bytes_field(3, b"bob")]);
    let actual_group = message([bytes_field(3, b"bob"), bytes_field(3, b"alice")]);
    let expected = body(message([bytes_field(
        3,
        &message([bytes_field(1, &message([bytes_field(6, &expected_group)]))]),
    )]));
    let actual = body(message([bytes_field(
        3,
        &message([bytes_field(1, &message([bytes_field(6, &actual_group)]))]),
    )]));

    let discovery = discover_protobuf_order(&expected, &actual).unwrap();

    assert_eq!(
        discovery.unordered_paths,
        vec![ProtobufFieldPath(vec![3, 1, 6, 3])]
    );
    assert!(discovery.order_only);
    let rules = discovery
        .unordered_paths
        .iter()
        .cloned()
        .map(|field_path| ProtobufUnorderedPath {
            display_path: field_path.display_path(),
            field_path,
            element_type: ProtobufRepeatedElementType::String,
            source_evidence: "test source contract".to_string(),
        })
        .collect::<Vec<_>>();
    assert!(compare_protobuf(&expected, &actual, &rules, &[]).unwrap());
}

#[test]
fn changed_repeated_value_is_not_hidden() {
    let expected = body(message([bytes_field(3, b"alice"), bytes_field(3, b"bob")]));
    let actual = body(message([bytes_field(3, b"bob"), bytes_field(3, b"carol")]));

    let discovery = discover_protobuf_order(&expected, &actual).unwrap();

    assert!(discovery.unordered_paths.is_empty());
    assert!(!discovery.order_only);
}

#[test]
fn absent_unordered_path_is_a_no_op_without_hiding_presence_mismatch() {
    let absent = body(message([varint_field(1, 81), varint_field(4, 0)]));
    let present = body(message([bytes_field(
        3,
        &message([bytes_field(3, &message([bytes_field(2, &message([]))]))]),
    )]));
    let rule = ProtobufUnorderedPath {
        field_path: ProtobufFieldPath(vec![3, 3, 2]),
        display_path: "rule_collection.group_config.groups".to_string(),
        element_type: ProtobufRepeatedElementType::Message,
        source_evidence: "test source contract".to_string(),
    };

    assert!(compare_protobuf(&absent, &absent, std::slice::from_ref(&rule), &[]).unwrap());
    assert!(!compare_protobuf(&absent, &present, &[rule], &[]).unwrap());
}

#[test]
fn present_unordered_path_still_requires_compatible_wire_types() {
    let malformed = body(message([bytes_field(
        3,
        &message([bytes_field(3, &message([varint_field(2, 1)]))]),
    )]));
    let rule = ProtobufUnorderedPath {
        field_path: ProtobufFieldPath(vec![3, 3, 2]),
        display_path: "rule_collection.group_config.groups".to_string(),
        element_type: ProtobufRepeatedElementType::Message,
        source_evidence: "test source contract".to_string(),
    };

    let error = compare_protobuf(&malformed, &malformed, &[rule], &[]).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("protobuf Message repeated field is not length-delimited")
    );
}

#[test]
fn rejects_invalid_envelope_length() {
    assert!(discover_protobuf_order(&[3, 0, 0, 0, 2, 8], &[3, 0, 0, 0, 1, 8]).is_err());
}

#[test]
fn compares_packed_integer_elements_without_treating_bytes_as_a_collection() {
    let expected = body(message([bytes_field(2, &[1, 0x80, 1, 2])]));
    let actual = body(message([bytes_field(2, &[2, 1, 0x80, 1])]));
    let rule = ProtobufUnorderedPath {
        field_path: ProtobufFieldPath(vec![2]),
        display_path: "config_scene.values".to_string(),
        element_type: ProtobufRepeatedElementType::Uint32,
        source_evidence: "test source contract".to_string(),
    };

    let (matches, discovery) = evaluate_protobuf(&expected, &actual, &[rule], &[]).unwrap();

    assert!(matches);
    assert!(discovery.order_only);
    assert_eq!(discovery.unordered_paths, vec![ProtobufFieldPath(vec![2])]);
    assert_eq!(
        discovery.differences,
        vec![ProtobufBodyDifference {
            field_path: ProtobufFieldPath(vec![2]),
            display_path: "config_scene.values".to_string(),
            kind: ProtobufBodyDifferenceKind::RepeatedFieldOrderMismatch,
        }]
    );
}

#[test]
fn discovers_inner_then_outer_message_order() {
    let entry = |key: &[u8], values: [&[u8]; 2]| {
        message([
            bytes_field(1, key),
            bytes_field(2, &message([bytes_field(1, values[0])])),
            bytes_field(2, &message([bytes_field(1, values[1])])),
        ])
    };
    let expected = body(message([bytes_field(
        3,
        &message([
            bytes_field(3, &entry(b"a", [b"x", b"y"])),
            bytes_field(3, &entry(b"b", [b"p", b"q"])),
        ]),
    )]));
    let actual = body(message([bytes_field(
        3,
        &message([
            bytes_field(3, &entry(b"b", [b"q", b"p"])),
            bytes_field(3, &entry(b"a", [b"y", b"x"])),
        ]),
    )]));

    let discovery = discover_protobuf_order(&expected, &actual).unwrap();

    assert_eq!(
        discovery.unordered_paths,
        vec![
            ProtobufFieldPath(vec![3, 3]),
            ProtobufFieldPath(vec![3, 3, 2]),
        ]
    );
    assert!(discovery.order_only);
    let rules = [
        ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3, 3, 2]),
            display_path: "rule_collection.group_config.values".to_string(),
            element_type: ProtobufRepeatedElementType::Message,
            source_evidence: "test source contract".to_string(),
        },
        ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![3, 3]),
            display_path: "rule_collection.group_config".to_string(),
            element_type: ProtobufRepeatedElementType::Message,
            source_evidence: "test source contract".to_string(),
        },
    ];
    assert!(compare_protobuf(&expected, &actual, &rules, &[]).unwrap());
}

#[test]
fn discovers_and_applies_a_joined_string_field() {
    let expected = body(message([bytes_field(3, b"alice,,bob,alice")]));
    let actual = body(message([bytes_field(3, b"alice,bob,alice,")]));

    let discovery = discover_protobuf_order(&expected, &actual).unwrap();

    assert_eq!(
        discovery.unordered_joined_string_paths,
        vec![(ProtobufFieldPath(vec![3]), ",".to_string())]
    );
    assert!(discovery.candidates_explain_all_differences);
    assert!(!discovery.order_only);
    let rule = ProtobufJoinedStringPath {
        field_path: ProtobufFieldPath(vec![3]),
        display_path: "response.names".to_string(),
        field_type: ProtobufJoinedStringFieldType::String,
        separator: ",".to_string(),
        source_evidence: "src/service.rs:names is set-joined".to_string(),
    };

    let (matches, evaluated) = evaluate_protobuf(&expected, &actual, &[], &[rule]).unwrap();

    assert!(matches);
    assert!(evaluated.order_only);
    assert_eq!(
        evaluated.differences,
        vec![ProtobufBodyDifference {
            field_path: ProtobufFieldPath(vec![3]),
            display_path: "response.names".to_string(),
            kind: ProtobufBodyDifferenceKind::JoinedStringOrderMismatch,
        }]
    );
}

#[test]
fn discards_auto_discovered_joined_string_path_that_also_selects_binary() {
    let expected = body(message([
        bytes_field(3, &message([bytes_field(1, b"alice,bob")])),
        bytes_field(3, &message([bytes_field(1, &[0xff, 0x2c, 0x80])])),
    ]));
    let actual = body(message([
        bytes_field(3, &message([bytes_field(1, b"bob,alice")])),
        bytes_field(3, &message([bytes_field(1, &[0xff, 0x2c, 0x80])])),
    ]));

    let discovery = discover_protobuf_order(&expected, &actual).unwrap();

    assert!(discovery.unordered_joined_string_paths.is_empty());
    assert!(!discovery.candidates_explain_all_differences);
    assert!(!evaluate_protobuf(&expected, &actual, &[], &[]).unwrap().0);

    let rule = ProtobufJoinedStringPath {
        field_path: ProtobufFieldPath(vec![3, 1]),
        display_path: "response.names".to_string(),
        field_type: ProtobufJoinedStringFieldType::String,
        separator: ",".to_string(),
        source_evidence: "test source contract".to_string(),
    };
    let error = compare_protobuf(&expected, &actual, &[], &[rule]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("protobuf joined-string field is not UTF-8")
    );
}

#[test]
fn joined_string_rule_preserves_duplicate_multiplicity() {
    let expected = body(message([bytes_field(3, b"alice,bob,alice")]));
    let actual = body(message([bytes_field(3, b"bob,alice")]));
    let rule = ProtobufJoinedStringPath {
        field_path: ProtobufFieldPath(vec![3]),
        display_path: "response.names".to_string(),
        field_type: ProtobufJoinedStringFieldType::String,
        separator: ",".to_string(),
        source_evidence: "src/service.rs:names is set-joined".to_string(),
    };

    assert!(!compare_protobuf(&expected, &actual, &[], &[rule]).unwrap());
}
