use anyhow::{Result, ensure};

use super::super::super::response::{
    ResponseBodyCodec, ResponseBodyJoinedStringPath, ResponseBodyUnorderedPath,
};
use crate::replay::{is_hessian2_body, is_protobuf_body};

pub(super) fn validate_unreported_codec_candidate(
    case_id: &str,
    codec: ResponseBodyCodec,
    expected: &[u8],
    actual: &[u8],
) -> Result<()> {
    match codec {
        ResponseBodyCodec::Protobuf => {
            ensure!(
                is_protobuf_body(expected),
                "case {case_id:?} source-before body is not valid protobuf response-body evidence"
            );
            ensure!(
                is_protobuf_body(actual),
                "case {case_id:?} candidate body is not valid protobuf response-body evidence"
            );
        }
        ResponseBodyCodec::Hessian2 => {
            ensure!(
                is_hessian2_body(expected),
                "case {case_id:?} source-before body is not one complete Hessian2 value in a supported body envelope"
            );
            ensure!(
                is_hessian2_body(actual),
                "case {case_id:?} candidate body is not one complete Hessian2 value in a supported body envelope"
            );
        }
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
    Ok(())
}

pub(super) fn compare_response_body(
    expected: &[u8],
    actual: &[u8],
    codec: ResponseBodyCodec,
    unordered_paths: &[ResponseBodyUnorderedPath],
    joined_string_paths: &[ResponseBodyJoinedStringPath],
) -> Result<bool> {
    match codec {
        ResponseBodyCodec::Protobuf => crate::replay::assertion::protobuf::compare_protobuf(
            expected,
            actual,
            &protobuf_unordered(unordered_paths)?,
            &protobuf_joined(joined_string_paths)?,
        ),
        ResponseBodyCodec::Hessian2 => crate::replay::assertion::hessian2::compare_hessian2(
            expected,
            actual,
            &hessian2_unordered(unordered_paths)?,
            &hessian2_joined(joined_string_paths)?,
        ),
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
}

pub(super) fn selected_response_body_paths_match(
    expected: &[u8],
    actual: &[u8],
    codec: ResponseBodyCodec,
    effective_unordered: &[ResponseBodyUnorderedPath],
    effective_joined: &[ResponseBodyJoinedStringPath],
    selected_unordered: &[ResponseBodyUnorderedPath],
    selected_joined: &[ResponseBodyJoinedStringPath],
) -> Result<bool> {
    match codec {
        ResponseBodyCodec::Protobuf => crate::replay::assertion::protobuf::selected_paths_match(
            expected,
            actual,
            &protobuf_unordered(effective_unordered)?,
            &protobuf_joined(effective_joined)?,
            &protobuf_unordered(selected_unordered)?,
            &protobuf_joined(selected_joined)?,
        ),
        ResponseBodyCodec::Hessian2 => crate::replay::assertion::hessian2::selected_paths_match(
            expected,
            actual,
            &hessian2_unordered(effective_unordered)?,
            &hessian2_joined(effective_joined)?,
            &hessian2_unordered(selected_unordered)?,
            &hessian2_joined(selected_joined)?,
        ),
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
}

fn protobuf_unordered(
    paths: &[ResponseBodyUnorderedPath],
) -> Result<Vec<crate::replay::policy::ProtobufUnorderedPath>> {
    paths
        .iter()
        .map(|path| match path {
            ResponseBodyUnorderedPath::Protobuf(path) => Ok(path.clone()),
            ResponseBodyUnorderedPath::Hessian2(_) => {
                anyhow::bail!("protobuf rule contains a Hessian2 unordered path")
            }
        })
        .collect()
}

fn protobuf_joined(
    paths: &[ResponseBodyJoinedStringPath],
) -> Result<Vec<crate::replay::policy::ProtobufJoinedStringPath>> {
    paths
        .iter()
        .map(|path| match path {
            ResponseBodyJoinedStringPath::Protobuf(path) => Ok(path.clone()),
            ResponseBodyJoinedStringPath::Hessian2(_) => {
                anyhow::bail!("protobuf rule contains a Hessian2 joined-string path")
            }
        })
        .collect()
}

fn hessian2_unordered(
    paths: &[ResponseBodyUnorderedPath],
) -> Result<Vec<crate::replay::policy::Hessian2UnorderedPath>> {
    paths
        .iter()
        .map(|path| match path {
            ResponseBodyUnorderedPath::Hessian2(path) => Ok(path.clone()),
            ResponseBodyUnorderedPath::Protobuf(_) => {
                anyhow::bail!("Hessian2 rule contains a protobuf unordered path")
            }
        })
        .collect()
}

fn hessian2_joined(
    paths: &[ResponseBodyJoinedStringPath],
) -> Result<Vec<crate::replay::policy::Hessian2JoinedStringPath>> {
    paths
        .iter()
        .map(|path| match path {
            ResponseBodyJoinedStringPath::Hessian2(path) => Ok(path.clone()),
            ResponseBodyJoinedStringPath::Protobuf(_) => {
                anyhow::bail!("Hessian2 rule contains a protobuf joined-string path")
            }
        })
        .collect()
}
