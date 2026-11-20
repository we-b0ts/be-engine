//! Physical key positions, independent of identities or recording lifecycle.
use anyhow::{Context, Result, ensure};
use std::ops::Range;

pub(crate) fn script_key_slots(count: &[u8], argument_count: usize) -> Result<Range<usize>> {
    let count = std::str::from_utf8(count)?.parse::<usize>()?;
    let end = count
        .checked_add(2)
        .context("Redis script key count overflow")?;
    ensure!(
        end <= argument_count,
        "Redis script key count exceeds arguments"
    );
    Ok(2..end)
}

pub fn key_indices(command: &str, args: &[Vec<u8>]) -> Result<Vec<usize>> {
    let indices = match command {
        "MGET" | "DEL" | "UNLINK" | "EXISTS" | "TOUCH" | "SDIFF" | "SINTER" | "SUNION"
        | "PFCOUNT" => (0..args.len()).collect(),
        "MSET" | "MSETNX" => {
            ensure!(
                args.len().is_multiple_of(2),
                "Redis key/value pairs are incomplete"
            );
            (0..args.len()).step_by(2).collect()
        }
        "RENAME" | "RENAMENX" | "RPOPLPUSH" | "BRPOPLPUSH" | "SMOVE" | "LMOVE" | "BLMOVE"
        | "COPY" => {
            ensure!(args.len() >= 2, "Redis command requires two keys");
            vec![0, 1]
        }
        "EVAL" | "EVALSHA" => {
            ensure!(args.len() >= 2, "Redis script key count is absent");
            script_key_slots(&args[1], args.len())?.collect()
        }
        "DELEX" | "GET" | "SET" | "SETNX" | "SETEX" | "PSETEX" | "GETSET" | "GETDEL" | "GETEX"
        | "APPEND" | "STRLEN" | "GETRANGE" | "SETRANGE" | "INCR" | "INCRBY" | "INCRBYFLOAT"
        | "DECR" | "DECRBY" | "TTL" | "PTTL" | "EXPIRE" | "PEXPIRE" | "EXPIREAT" | "PEXPIREAT"
        | "PERSIST" | "TYPE" | "DUMP" | "RESTORE" | "HGET" | "HMGET" | "HGETALL" | "HSET"
        | "HMSET" | "HSETNX" | "HDEL" | "HEXISTS" | "HKEYS" | "HVALS" | "HLEN" | "HINCRBY"
        | "HINCRBYFLOAT" | "HSCAN" | "LPUSH" | "RPUSH" | "LPUSHX" | "RPUSHX" | "LPOP" | "RPOP"
        | "LLEN" | "LINDEX" | "LSET" | "LRANGE" | "LTRIM" | "LREM" | "LINSERT" | "LPOS"
        | "SADD" | "SREM" | "SMEMBERS" | "SISMEMBER" | "SMISMEMBER" | "SCARD" | "SPOP"
        | "SRANDMEMBER" | "SSCAN" | "ZADD" | "ZREM" | "ZSCORE" | "ZMSCORE" | "ZCARD" | "ZCOUNT"
        | "ZINCRBY" | "ZRANGE" | "ZREVRANGE" | "ZRANGEBYSCORE" | "ZREVRANGEBYSCORE" | "ZRANK"
        | "ZREVRANK" | "ZSCAN" | "ZREMRANGEBYSCORE" | "ZREMRANGEBYRANK" | "PFADD" | "XADD"
        | "XLEN" | "XRANGE" | "XREVRANGE" | "XTRIM" | "XDEL" => {
            ensure!(!args.is_empty(), "Redis command key is absent");
            vec![0]
        }
        _ => Vec::new(),
    };
    Ok(indices)
}
