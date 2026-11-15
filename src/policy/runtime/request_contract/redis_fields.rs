//! Logical Redis storage values, independently of command argument positions.
use super::*;

mod keys;
mod native;
mod projection;
mod runtime;
mod scalar;
pub(super) use scalar::ScalarDelivery;
mod time_copies;
mod time_writes;
pub(crate) use time_copies::PreparedRedisTimeRead;
pub(crate) use time_copies::{
    RedisTimeRead, redis_delivered_global_time_copies, redis_delivered_scalar_time_copies,
    redis_time_position,
};
pub(crate) use time_writes::PreparedRedisTimeWrite;
#[cfg(test)]
mod tests;

pub(crate) use traffic_protocol_redis::values::{
    RedisContainer, RedisFieldValue, redis_field_values,
};
pub(super) use traffic_protocol_redis::values::{bulk_prefix, response_identities};
