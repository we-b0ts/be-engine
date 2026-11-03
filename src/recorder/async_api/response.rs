//! Complete native Redis response facts shared by live and historical ends.
use super::decode;
use crate::DependencyExchangeOutcome;
use crate::policy::AsyncRedisResponse;
use crate::recorder::BodyCapture;
use bytes::Bytes;
use redis_protocol::resp2::types::BytesFrame as Resp2;
use redis_protocol::resp3::types::BytesFrame as Resp3;

pub(super) struct Exchange<'a> {
    pub(super) body: &'a BodyCapture,
    pub(super) kind: &'a str,
    pub(super) version: u8,
    pub(super) outcome: DependencyExchangeOutcome,
    pub(super) warnings: &'a [String],
}

#[derive(Clone, Copy)]
pub(super) enum Reply {
    Nil,
    Integer(i64),
    Value,
}

impl Reply {
    pub(super) fn matches(self, condition: AsyncRedisResponse) -> bool {
        match condition {
            AsyncRedisResponse::Any => true,
            AsyncRedisResponse::Nil => matches!(self, Self::Nil),
        }
    }
}

pub(super) fn complete(capture: &BodyCapture) -> Option<Vec<u8>> {
    let bytes = decode(capture)?;
    (capture.stored_len == capture.original_len && bytes.len() == capture.stored_len)
        .then_some(bytes)
}

pub(super) fn parse(exchange: Exchange<'_>) -> Option<Reply> {
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

#[cfg(test)]
mod tests;
