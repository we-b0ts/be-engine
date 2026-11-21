//! Complete native RESP reply facts for Source completion observations.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use redis_protocol::resp2::types::BytesFrame as Resp2;
use redis_protocol::resp3::types::BytesFrame as Resp3;
use traffic_model::{DependencyExchangeOutcome, capture::BodyCapture};

pub struct Exchange<'a> {
    pub body: &'a BodyCapture,
    pub kind: &'a str,
    pub version: u8,
    pub outcome: DependencyExchangeOutcome,
    pub warnings: &'a [String],
}

#[derive(Clone, Copy)]
pub enum Reply {
    Nil,
    Integer(i64),
    Value,
}

pub fn complete(capture: &BodyCapture) -> Option<Vec<u8>> {
    if capture.truncated {
        return None;
    }
    let bytes = match capture.encoding {
        "utf8" => capture.data.as_bytes().to_vec(),
        "base64" => STANDARD.decode(capture.data.as_bytes()).ok()?,
        _ => return None,
    };
    (capture.stored_len == capture.original_len && bytes.len() == capture.stored_len)
        .then_some(bytes)
}

pub fn parse(exchange: Exchange<'_>) -> Option<Reply> {
    if exchange.outcome != DependencyExchangeOutcome::Response
        || !exchange.warnings.is_empty()
        || matches!(exchange.kind, "error" | "blob_error")
    {
        return None;
    }
    let bytes = Bytes::from(complete(exchange.body)?);
    let (reply, consumed) = match exchange.version {
        2 => {
            let (frame, consumed) = redis_protocol::resp2::decode::decode_bytes(&bytes).ok()??;
            let reply = match frame {
                Resp2::Error(_) => return None,
                Resp2::Null => Reply::Nil,
                Resp2::Integer(value) => Reply::Integer(value),
                _ => Reply::Value,
            };
            (reply, consumed)
        }
        3 => {
            let (frame, consumed) =
                redis_protocol::resp3::decode::complete::decode_bytes(&bytes).ok()??;
            let reply = match frame {
                Resp3::SimpleError { .. }
                | Resp3::BlobError { .. }
                | Resp3::Push { .. }
                | Resp3::Hello { .. }
                | Resp3::ChunkedString(_) => return None,
                Resp3::Null => Reply::Nil,
                Resp3::Number { data, .. } => Reply::Integer(data),
                _ => Reply::Value,
            };
            (reply, consumed)
        }
        _ => return None,
    };
    (consumed == bytes.len()).then_some(reply)
}
