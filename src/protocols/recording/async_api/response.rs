//! Bind the authored response condition to native RESP facts.
use crate::policy::AsyncRedisResponse;
pub(super) use traffic_protocol_redis::capture::response::{Exchange, Reply, complete, parse};

pub(super) fn matches(reply: Reply, condition: AsyncRedisResponse) -> bool {
    match condition {
        AsyncRedisResponse::Any => true,
        AsyncRedisResponse::Nil => matches!(reply, Reply::Nil),
    }
}

#[cfg(test)]
mod tests;
