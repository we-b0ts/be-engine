//! Logical Redis storage values, independently of command argument positions.
use super::*;
use crate::policy::RedisContainer;
use std::ops::Range;

mod keys;
mod native;
mod projection;
mod response;
pub(super) use response::bulk_prefix;
mod runtime;
mod scalar;
pub(super) use scalar::ScalarDelivery;
mod time_copies;
mod time_writes;
pub(in crate::replay) use time_copies::PreparedRedisTimeRead;
pub(crate) use time_copies::{
    RedisTimeRead, redis_delivered_global_time_copies, redis_delivered_scalar_time_copies,
    redis_time_position,
};
pub(in crate::replay) use time_writes::PreparedRedisTimeWrite;
#[cfg(test)]
mod tests;

/// One stored string, hash value, or list element. A miss has no payload.
#[derive(Debug, Clone)]
pub(crate) struct RedisFieldValue<'a> {
    pub container: RedisContainer,
    pub key: &'a [u8],
    pub hash_field: Option<&'a [u8]>,
    pub payload: Option<&'a [u8]>,
    pub(super) stored: bool,
    pub argument: Option<usize>,
    pub response: Option<Range<usize>>,
}

/// Resolve physical storage values without granting a key, field, or operation permission.
pub(crate) fn redis_field_values<'a>(
    command: &str,
    args: &'a [Vec<u8>],
    response: Option<&'a [u8]>,
) -> Result<Vec<RedisFieldValue<'a>>> {
    ensure!(
        args.len() <= 16384,
        "Redis value carrier argument bound exceeded"
    );
    if let Some(response) = response {
        return self::response::values(command, args, response);
    }
    let mut values = Vec::new();
    let mut push = |container, key: usize, field: Option<usize>, index: usize| {
        values.push(RedisFieldValue {
            container,
            key: &args[key],
            hash_field: field.map(|index| args[index].as_slice()),
            payload: Some(&args[index]),
            stored: true,
            argument: Some(index),
            response: None,
        });
    };
    use RedisContainer::*;
    match command {
        "SET" => {
            ensure!(args.len() >= 2, "SET requires a key and value");
            push(String, 0, None, 1);
        }
        "SETEX" | "PSETEX" => {
            ensure!(args.len() == 3, "{command} requires a key, TTL and value");
            push(String, 0, None, 2);
        }
        "MSET" => {
            ensure!(
                args.len() >= 2 && args.len().is_multiple_of(2),
                "MSET requires complete key/value pairs"
            );
            for key in (0..args.len()).step_by(2) {
                push(String, key, None, key + 1);
            }
        }
        "HSET" | "HMSET" => {
            ensure!(
                args.len() >= 3 && (args.len() - 1).is_multiple_of(2),
                "{command} requires complete hash field/value pairs"
            );
            for field in (1..args.len()).step_by(2) {
                push(Hash, 0, Some(field), field + 1);
            }
        }
        "RPUSH" | "LPUSH" => {
            ensure!(
                args.len() >= 2,
                "{command} requires a key and list elements"
            );
            for index in 1..args.len() {
                push(List, 0, None, index);
            }
        }
        "LSET" => {
            ensure!(args.len() == 3, "LSET requires a key, index and value");
            push(List, 0, None, 2);
        }
        "EVAL" | "EVALSHA" => {
            ensure!(args.len() >= 2, "{command} requires script and key count");
            let keys = std::str::from_utf8(&args[1])
                .context("Redis script key count is not UTF-8")?
                .parse::<usize>()
                .context("Redis script key count is invalid")?;
            let start = keys
                .checked_add(2)
                .context("Redis script key count overflow")?;
            ensure!(
                start <= args.len(),
                "Redis script key count exceeds arguments"
            );
            for index in start..args.len() {
                values.push(RedisFieldValue {
                    container: String,
                    key: if keys == 0 { &[] } else { &args[2] },
                    hash_field: None,
                    payload: Some(&args[index]),
                    stored: false,
                    argument: Some(index),
                    response: None,
                });
            }
        }
        _ => {}
    }
    Ok(values)
}

/// Immutable request identities that may expose values in a response.
pub(crate) fn response_identities<'a>(
    command: &str,
    args: &'a [Vec<u8>],
) -> Result<Vec<RedisFieldValue<'a>>> {
    ensure!(
        args.len() <= 16384,
        "Redis response identity bound exceeded"
    );
    let mut values = Vec::new();
    let mut push = |container, key: usize, field: Option<usize>| {
        values.push(RedisFieldValue {
            container,
            key: &args[key],
            hash_field: field.map(|index| args[index].as_slice()),
            payload: None,
            stored: true,
            argument: None,
            response: None,
        });
    };
    use RedisContainer::*;
    match command {
        "GET" => {
            ensure!(args.len() == 1, "GET requires exactly one key");
            push(String, 0, None);
        }
        "MGET" => {
            ensure!(!args.is_empty(), "MGET requires keys");
            for index in 0..args.len() {
                push(String, index, None);
            }
        }
        "HGET" => {
            ensure!(args.len() == 2, "HGET requires a key and hash field");
            push(Hash, 0, Some(1));
        }
        "HMGET" => {
            ensure!(args.len() >= 2, "HMGET requires a key and hash fields");
            for field in 1..args.len() {
                push(Hash, 0, Some(field));
            }
        }
        "HGETALL" => {
            ensure!(args.len() == 1, "HGETALL requires exactly one key");
            push(Hash, 0, None);
        }
        "LRANGE" => {
            ensure!(args.len() == 3, "LRANGE requires a key and two indices");
            push(List, 0, None);
        }
        "LINDEX" => {
            ensure!(args.len() == 2, "LINDEX requires a key and index");
            push(List, 0, None);
        }
        _ => {}
    }
    Ok(values)
}
