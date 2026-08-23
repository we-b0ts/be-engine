use anyhow::{Result, ensure};

use super::super::super::response::{
    Hessian2JoinedStringPath, ResponseBodyCodec, ResponseBodyUnorderedPath,
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
    joined_string_paths: &[Hessian2JoinedStringPath],
) -> Result<bool> {
    match codec {
        ResponseBodyCodec::Protobuf => {
            ensure!(
                joined_string_paths.is_empty(),
                "protobuf rule cannot carry joined-string paths"
            );
            let paths = unordered_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyUnorderedPath::Protobuf(path) => Ok(path.clone()),
                    ResponseBodyUnorderedPath::Hessian2(_) => {
                        anyhow::bail!("protobuf rule contains a Hessian2 unordered path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            crate::replay::assertion::protobuf::compare_protobuf(expected, actual, &paths)
        }
        ResponseBodyCodec::Hessian2 => {
            let paths = unordered_paths
                .iter()
                .map(|path| match path {
                    ResponseBodyUnorderedPath::Hessian2(path) => Ok(path.clone()),
                    ResponseBodyUnorderedPath::Protobuf(_) => {
                        anyhow::bail!("Hessian2 rule contains a protobuf unordered path")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            crate::replay::assertion::hessian2::compare_hessian2(
                expected,
                actual,
                &paths,
                joined_string_paths,
            )
        }
        codec => anyhow::bail!("unsupported structured response body codec {codec:?}"),
    }
}
