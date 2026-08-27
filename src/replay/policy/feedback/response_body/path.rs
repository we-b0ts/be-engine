use super::super::super::response::{
    Hessian2ValuePath, ProtobufFieldPath, ResponseBodyCodec, ResponseBodyJoinedStringPath,
    ResponseBodyUnorderedPath,
};
use crate::replay::{
    Hessian2JoinedStringCandidate, Hessian2ValuePathCandidate, ProtobufFieldPathCandidate,
    ProtobufJoinedStringCandidate, ResponseBodyDifferenceDetail, ResponseBodyJoinedStringCandidate,
    ResponseBodyUnorderedPathCandidate,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum BodyPath {
    Protobuf(ProtobufFieldPath),
    ProtobufJoinedString(ProtobufFieldPath),
    Hessian2(Hessian2ValuePath),
    Hessian2JoinedString(Hessian2ValuePath),
}

pub(super) fn display(path: &BodyPath) -> String {
    match path {
        BodyPath::Protobuf(field_path) | BodyPath::ProtobufJoinedString(field_path) => {
            field_path.display_path()
        }
        BodyPath::Hessian2(value_path) | BodyPath::Hessian2JoinedString(value_path) => {
            value_path.display_path()
        }
    }
}

pub(super) fn from_rule(path: &ResponseBodyUnorderedPath) -> BodyPath {
    match path {
        ResponseBodyUnorderedPath::Protobuf(path) => BodyPath::Protobuf(path.field_path.clone()),
        ResponseBodyUnorderedPath::Hessian2(path) => BodyPath::Hessian2(path.value_path.clone()),
    }
}

pub(super) fn from_joined_string_rule(path: &ResponseBodyJoinedStringPath) -> BodyPath {
    match path {
        ResponseBodyJoinedStringPath::Protobuf(path) => {
            BodyPath::ProtobufJoinedString(path.field_path.clone())
        }
        ResponseBodyJoinedStringPath::Hessian2(path) => {
            BodyPath::Hessian2JoinedString(path.value_path.clone())
        }
    }
}

pub(super) fn from_candidate(
    path: &ResponseBodyUnorderedPathCandidate,
    codec: ResponseBodyCodec,
) -> Option<BodyPath> {
    match (path, codec) {
        (ResponseBodyUnorderedPathCandidate::Protobuf(path), ResponseBodyCodec::Protobuf) => {
            Some(BodyPath::Protobuf(path.field_path.clone()))
        }
        (ResponseBodyUnorderedPathCandidate::Hessian2(path), ResponseBodyCodec::Hessian2) => {
            Some(BodyPath::Hessian2(path.value_path.clone()))
        }
        _ => None,
    }
}

pub(super) fn from_joined_string_candidate(
    path: &ResponseBodyJoinedStringCandidate,
    codec: ResponseBodyCodec,
) -> Option<BodyPath> {
    match (path, codec) {
        (ResponseBodyJoinedStringCandidate::Protobuf(path), ResponseBodyCodec::Protobuf) => {
            Some(BodyPath::ProtobufJoinedString(path.field_path.clone()))
        }
        (ResponseBodyJoinedStringCandidate::Hessian2(path), ResponseBodyCodec::Hessian2) => {
            Some(BodyPath::Hessian2JoinedString(path.value_path.clone()))
        }
        _ => None,
    }
}

pub(super) fn from_difference(
    difference: &ResponseBodyDifferenceDetail,
    codec: ResponseBodyCodec,
) -> Option<BodyPath> {
    match (difference, codec) {
        (ResponseBodyDifferenceDetail::Protobuf(difference), ResponseBodyCodec::Protobuf) => {
            Some(BodyPath::Protobuf(difference.field_path.clone()))
        }
        (ResponseBodyDifferenceDetail::Hessian2(difference), ResponseBodyCodec::Hessian2) => {
            Some(BodyPath::Hessian2(difference.value_path.clone()))
        }
        _ => None,
    }
}

pub(super) fn joined_string_location(path: BodyPath) -> BodyPath {
    match path {
        BodyPath::Protobuf(field_path) | BodyPath::ProtobufJoinedString(field_path) => {
            BodyPath::ProtobufJoinedString(field_path)
        }
        BodyPath::Hessian2(value_path) | BodyPath::Hessian2JoinedString(value_path) => {
            BodyPath::Hessian2JoinedString(value_path)
        }
    }
}

pub(super) fn into_candidate(path: BodyPath) -> ResponseBodyUnorderedPathCandidate {
    match path {
        BodyPath::Protobuf(field_path) => ResponseBodyUnorderedPathCandidate::Protobuf(
            ProtobufFieldPathCandidate::from(field_path),
        ),
        BodyPath::Hessian2(value_path) => ResponseBodyUnorderedPathCandidate::Hessian2(
            Hessian2ValuePathCandidate::from(value_path),
        ),
        BodyPath::ProtobufJoinedString(_) | BodyPath::Hessian2JoinedString(_) => {
            unreachable!("joined-string body paths carry separators")
        }
    }
}

pub(super) fn into_joined_string_candidate(
    path: BodyPath,
    separator: String,
) -> ResponseBodyJoinedStringCandidate {
    match path {
        BodyPath::ProtobufJoinedString(field_path) => ResponseBodyJoinedStringCandidate::Protobuf(
            ProtobufJoinedStringCandidate::from((field_path, separator)),
        ),
        BodyPath::Hessian2JoinedString(value_path) => ResponseBodyJoinedStringCandidate::Hessian2(
            Hessian2JoinedStringCandidate::from((value_path, separator)),
        ),
        _ => unreachable!("joined-string candidate requires a joined-string body path"),
    }
}
