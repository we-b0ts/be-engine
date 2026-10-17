use super::*;
use crate::policy::{
    FieldContract, ProtobufCodec, ProtobufField, ProtobufType as Type, TimeAnchor, TimeRelation,
    TimestampFormat,
};
use crate::value_contract::{
    json::{self, AnchorClocks, Field},
    time::ClockPair,
};
use serde_json::json;
use std::collections::BTreeMap;

fn codec(fields: &[(&str, &[u32], Type, bool)]) -> Codec {
    Codec::Protobuf(ProtobufCodec {
        fields: fields
            .iter()
            .map(|(name, path, kind, repeated)| {
                (
                    (*name).into(),
                    ProtobufField {
                        field_path: path.to_vec(),
                        field_type: *kind,
                        repeated: *repeated,
                    },
                )
            })
            .collect(),
    })
}
fn varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(if value == 0 { byte } else { byte | 128 });
        if value == 0 {
            return output;
        }
    }
}
fn number(field: u32, value: u64) -> Vec<u8> {
    let mut output = varint(u64::from(field) << 3);
    output.extend(varint(value));
    output
}
fn bytes(field: u32, value: &[u8]) -> Vec<u8> {
    let mut output = varint((u64::from(field) << 3) | 2);
    output.extend(varint(value.len() as u64));
    output.extend(value);
    output
}
fn fixture() -> Codec {
    codec(&[
        ("/items", &[1], Type::Message, true),
        ("/items/*/id", &[1, 2], Type::Uint64, false),
        ("/items/*/created_at", &[1, 3], Type::Int64, false),
    ])
}
fn item(id: u64, time: u64, unknown: &str) -> Vec<u8> {
    bytes(
        1,
        &[number(2, id), number(3, time), bytes(9, unknown.as_bytes())].concat(),
    )
}
fn fields() -> BTreeMap<String, FieldContract> {
    BTreeMap::from([
        ("/items".into(), FieldContract::Unordered),
        (
            "/items/*/created_at".into(),
            FieldContract::Time {
                format: TimestampFormat::UnixSeconds,
                relation: TimeRelation::PreserveOffset,
                anchor: TimeAnchor::ApiRequestStart,
                utc_offset: None,
                clock_group: None,
            },
        ),
    ])
}
fn compare(source: &[u8], target: &[u8]) -> bool {
    let codec = fixture();
    let source = CodecView::decode(&codec, source).unwrap();
    let target = CodecView::decode(&codec, target).unwrap();
    let fields = fields();
    let paths = fields.keys().cloned().collect::<Vec<_>>();
    let field_views = fields
        .iter()
        .map(|(pointer, contract)| Field {
            rule_id: "example",
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    json::compare(
        &source.comparison_value(&paths),
        &target.comparison_value(&paths),
        &field_views,
        AnchorClocks {
            case: ClockPair {
                source: chrono::DateTime::from_timestamp(1000, 0),
                target: chrono::DateTime::from_timestamp(2000, 0),
            },
            ..Default::default()
        },
    )
    .passed()
}

#[test]
fn unordered_message_composition_preserves_stable_fields_and_per_element_unknowns() {
    let source = [item(11, 1000, "a"), item(22, 1001, "b"), number(10, 5)].concat();
    let target = [item(22, 2001, "b"), item(11, 2000, "a"), number(10, 5)].concat();
    assert!(compare(&source, &target));
    for target in [
        [item(22, 2001, "b"), item(11, 2000, "wrong"), number(10, 5)].concat(),
        [item(22, 2001, "b"), item(11, 2000, "a"), number(10, 6)].concat(),
        [item(11, 2000, "a"), item(11, 2000, "a"), number(10, 5)].concat(),
        [item(22, 2001, "b"), item(11, 2002, "a"), number(10, 5)].concat(),
    ] {
        assert!(!compare(&source, &target));
    }
}

#[test]
fn codec_declarations_do_not_authorize_raw_normalization() {
    let codec = codec(&[("/value", &[1], Type::Uint64, false)]);
    let canonical = CodecView::decode(&codec, &[8, 1]).unwrap();
    let noncanonical = CodecView::decode(&codec, &[8, 0x81, 0]).unwrap();
    assert_eq!(canonical.logical["value"], noncanonical.logical["value"]);
    assert_ne!(
        canonical.comparison_value(&[]),
        noncanonical.comparison_value(&[])
    );
    assert_eq!(
        canonical.comparison_value(&["/value".into()]),
        noncanonical.comparison_value(&["/value".into()])
    );
    assert_eq!(
        noncanonical.encode(&noncanonical.logical, &[]).unwrap(),
        [8, 0x81, 0]
    );
}

#[test]
fn packed_and_unpacked_repeated_values_keep_multiplicity_and_order_until_authorized() {
    let codec = codec(&[("/numbers", &[1], Type::Uint32, true)]);
    let packed = CodecView::decode(&codec, &bytes(1, &[1, 2, 2])).unwrap();
    let unpacked =
        CodecView::decode(&codec, &[number(1, 1), number(1, 2), number(1, 2)].concat()).unwrap();
    assert_eq!(packed.logical["numbers"], json!([1, 2, 2]));
    assert_ne!(packed.comparison_value(&[]), unpacked.comparison_value(&[]));
    assert_eq!(
        packed.comparison_value(&["/numbers".into()]),
        unpacked.comparison_value(&["/numbers".into()])
    );
    let original = bytes(1, &[0x81, 0, 2, 2]);
    let decoded = CodecView::decode(&codec, &original).unwrap();
    let mut edited = decoded.logical.clone();
    edited["numbers"][1] = json!(128);
    let output = decoded.encode(&edited, &["/numbers/1".into()]).unwrap();
    assert_eq!(output, bytes(1, &[0x81, 0, 0x80, 1, 2]));
}

#[test]
fn delivery_recomputes_message_lengths_and_preserves_every_unselected_byte() {
    let codec = fixture();
    let stable_noncanonical = vec![0x50, 0x85, 0];
    let original = [item(7, 127, "unknown"), stable_noncanonical.clone()].concat();
    let decoded = CodecView::decode(&codec, &original).unwrap();
    let mut edited = decoded.logical.clone();
    edited["items"][0]["created_at"] = json!(128);
    let allowed = vec!["/items/*/created_at".into()];
    assert_eq!(
        decoded.encode(&edited, &allowed).unwrap(),
        [item(7, 128, "unknown"), stable_noncanonical].concat()
    );
    assert!(decoded.encode(&edited, &[]).is_err());
    edited["items"][0]["id"] = json!(8);
    assert!(decoded.encode(&edited, &allowed).is_err());
    let mut edited = decoded.logical.clone();
    edited[protobuf::INTERNAL_KEY] = json!({});
    assert!(decoded.encode(&edited, &["".into()]).is_err());
    let mut edited = decoded.logical.clone();
    edited["added"] = json!(1);
    assert!(decoded.encode(&edited, &["/added".into()]).is_err());
    let mut edited = decoded.logical.clone();
    edited["items"][0]["created_at"] = json!("128");
    assert!(decoded.encode(&edited, &allowed).is_err());
}

#[test]
fn repeated_scalar_element_contracts_release_only_selected_raw_elements() {
    let codec = codec(&[("/numbers", &[1], Type::Uint32, true)]);
    let original = bytes(1, &[0xe8, 7, 0xe9, 7]);
    let shifted = bytes(1, &[0xd0, 15, 0xd1, 15]);
    let source = CodecView::decode(&codec, &original).unwrap();
    let target = CodecView::decode(&codec, &shifted).unwrap();
    let contract = FieldContract::Time {
        format: TimestampFormat::UnixSeconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::ApiRequestStart,
        utc_offset: None,
        clock_group: None,
    };
    let paths = ["/numbers/*".into()];
    assert!(
        json::compare(
            &source.comparison_value(&paths),
            &target.comparison_value(&paths),
            &[Field {
                rule_id: "times",
                pointer: "/numbers/*",
                contract: &contract
            }],
            AnchorClocks {
                case: ClockPair {
                    source: chrono::DateTime::from_timestamp(1000, 0),
                    target: chrono::DateTime::from_timestamp(2000, 0)
                },
                ..Default::default()
            }
        )
        .passed()
    );

    let canonical = CodecView::decode(&codec, &bytes(1, &[1, 2])).unwrap();
    let selected_noncanonical = CodecView::decode(&codec, &bytes(1, &[0x81, 0, 2])).unwrap();
    let unselected_noncanonical = CodecView::decode(&codec, &bytes(1, &[1, 0x82, 0])).unwrap();
    let paths = ["/numbers/0".into()];
    assert_eq!(
        canonical.comparison_value(&paths),
        selected_noncanonical.comparison_value(&paths)
    );
    assert_ne!(
        canonical.comparison_value(&paths),
        unselected_noncanonical.comparison_value(&paths)
    );
}

#[test]
fn ancestor_length_encoding_class_is_preserved_in_comparison_and_delivery() {
    let codec = fixture();
    let canonical = item(7, 127, "unknown");
    assert!(canonical[1] < 128);
    let noncanonical = [
        vec![canonical[0], canonical[1] | 128, 0],
        canonical[2..].to_vec(),
    ]
    .concat();
    let source = CodecView::decode(&codec, &canonical).unwrap();
    let padded = CodecView::decode(&codec, &noncanonical).unwrap();
    let paths = ["/items/*/created_at".into()];
    assert_ne!(
        source.comparison_value(&paths),
        padded.comparison_value(&paths)
    );
    let mut logical = padded.logical.clone();
    logical["items"][0]["created_at"] = json!(128);
    let output = padded.encode(&logical, &paths).unwrap();
    let expected = item(7, 128, "unknown");
    assert_eq!(
        output,
        [
            vec![expected[0], expected[1] | 128, 0],
            expected[2..].to_vec()
        ]
        .concat()
    );
}

#[test]
fn explicit_scalar_types_preserve_signed_and_unsigned_integer_precision() {
    let codec = codec(&[
        ("/signed", &[1], Type::Int64, false),
        ("/unsigned", &[2], Type::Uint64, false),
        ("/zigzag", &[3], Type::Sint32, false),
        ("/text", &[4], Type::String, false),
    ]);
    let original = [
        number(1, (-2_i64) as u64),
        number(2, u64::MAX),
        number(3, 3),
        bytes(4, b"ok"),
    ]
    .concat();
    let decoded = CodecView::decode(&codec, &original).unwrap();
    assert_eq!(decoded.logical["signed"], json!(-2));
    assert_eq!(decoded.logical["unsigned"], json!(u64::MAX));
    assert_eq!(decoded.logical["zigzag"], json!(-2));
    let mut edited = decoded.logical.clone();
    edited["zigzag"] = json!(-3);
    assert_eq!(
        decoded.encode(&edited, &["/zigzag".into()]).unwrap(),
        [
            number(1, (-2_i64) as u64),
            number(2, u64::MAX),
            number(3, 5),
            bytes(4, b"ok")
        ]
        .concat()
    );
}

#[test]
fn missing_presence_duplicate_singulars_wire_mismatches_and_limits_are_explicit() {
    let scalar = codec(&[("/value", &[1], Type::Uint32, false)]);
    let missing = CodecView::decode(&scalar, &[]).unwrap();
    let zero = CodecView::decode(&scalar, &[8, 0]).unwrap();
    assert!(missing.logical.get("value").is_none());
    assert_ne!(
        missing.comparison_value(&["/value".into()]),
        zero.comparison_value(&["/value".into()])
    );
    for bytes in [
        vec![8, 1, 8, 2],
        vec![10, 1, 1],
        vec![8, 0x80],
        vec![10, 5, 1],
        number(1, u64::MAX),
        vec![0],
    ] {
        assert!(CodecView::decode(&scalar, &bytes).is_err(), "{bytes:?}");
    }
    assert!(CodecView::decode(&scalar, &[8, 0].repeat(65_537)).is_err());
    assert!(CodecView::decode(&scalar, &vec![0; 1024 * 1024 + 1]).is_err());
    let string = codec(&[("/text", &[1], Type::String, false)]);
    assert!(CodecView::decode(&string, &bytes(1, &[255])).is_err());
    let implicit = codec(&[("/value", &[1, 2], Type::Uint32, false)]);
    assert!(
        CodecView::decode(
            &implicit,
            &[bytes(1, &number(2, 1)), bytes(1, &number(2, 2))].concat()
        )
        .is_err()
    );
}

#[test]
fn json_uses_duplicate_rejecting_decode_and_the_same_authorized_delivery_api() {
    assert!(CodecView::decode(&Codec::Json, br#"{"a":1,"a":2}"#).is_err());
    let decoded = CodecView::decode(&Codec::Json, br#"{ "time": 1, "stable": 7 }"#).unwrap();
    assert_eq!(
        decoded.encode(&decoded.logical, &[]).unwrap(),
        br#"{ "time": 1, "stable": 7 }"#
    );
    let mut edited = decoded.logical.clone();
    edited["time"] = json!(2);
    let output = decoded.encode(&edited, &["/time".into()]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap(),
        json!({"time":2,"stable":7})
    );
    edited["stable"] = json!(8);
    assert!(decoded.encode(&edited, &["/time".into()]).is_err());
    for value in [json!("2"), json!(2.0), json!(null)] {
        let mut edited = decoded.logical.clone();
        edited["time"] = value;
        assert!(decoded.encode(&edited, &["/time".into()]).is_err());
    }
}
