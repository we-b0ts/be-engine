use std::collections::BTreeMap;

use super::*;
use crate::policy::{ProtobufCodec, ProtobufField, TimeAnchor, TimeRelation};

#[test]
fn repeated_scalar_elements_keep_their_declared_type_without_changing_collection_ownership() {
    let codec = crate::value_codec::protobuf(ProtobufCodec {
        fields: BTreeMap::from([(
            "/numbers".into(),
            ProtobufField {
                field_path: vec![1],
                field_type: ProtobufType::Uint64,
                repeated: true,
            },
        )]),
    });
    let time = FieldContract::Time {
        format: TimestampFormat::UnixMicroseconds,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::DependencyRequestStart,
        utc_offset: None,
        clock_group: None,
        clock_scope: Default::default(),
    };
    assert!(validate_contract_binding(&codec, "/numbers/*", &time).is_ok());
    assert!(validate_contract_binding(&codec, "/numbers/0", &time).is_ok());
    assert!(validate_contract_binding(&codec, "/numbers", &time).is_err());
    assert!(validate_contract_binding(&codec, "/numbers/00", &time).is_err());
    assert!(validate_contract_binding(&codec, "/numbers/name", &time).is_err());
    assert!(validate_contract_binding(&codec, "/numbers/*/unknown", &time).is_err());
    assert!(validate_contract_binding(&codec, "/numbers", &FieldContract::Unordered).is_ok());
    assert!(validate_contract_binding(&codec, "/numbers/*", &FieldContract::Unordered).is_err());
}

#[test]
fn repeated_messages_never_infer_a_scalar_type_for_an_unbound_descendant() {
    let codec = crate::value_codec::protobuf(ProtobufCodec {
        fields: BTreeMap::from([(
            "/rows".into(),
            ProtobufField {
                field_path: vec![1],
                field_type: ProtobufType::Message,
                repeated: true,
            },
        )]),
    });
    let duration = FieldContract::Duration {
        unit: crate::policy::DurationUnit::Microseconds,
        anchor: TimeAnchor::DependencyRequestStart,
    };
    assert!(validate_contract_binding(&codec, "/rows/*", &duration).is_err());
    assert!(validate_contract_binding(&codec, "/rows/0", &duration).is_err());
    assert!(validate_contract_binding(&codec, "/rows/*/timestamp", &duration).is_err());
}
