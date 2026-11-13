//! Conservative Redis key-access exclusion shared by immutable Source proofs.
pub fn touches(command: &str, args: &[Vec<u8>], key: &[u8]) -> bool {
    match command {
        "EVAL" | "EVALSHA" | "EVAL_RO" | "EVALSHA_RO" => {
            // Redis scripts declare their complete key inventory after numkeys.
            // An absent, malformed or zero-key declaration gives no exclusion proof.
            let count = args
                .get(1)
                .and_then(|arg| std::str::from_utf8(arg).ok())
                .and_then(|text| text.parse::<usize>().ok());
            count
                .filter(|count| *count > 0)
                .and_then(|count| count.checked_add(2))
                .and_then(|end| args.get(2..end))
                .is_none_or(|keys| keys.iter().any(|candidate| candidate == key))
        }
        "SCRIPT" => !args.first().is_some_and(|subcommand| {
            ["LOAD", "EXISTS", "FLUSH"]
                .iter()
                .any(|name| subcommand.eq_ignore_ascii_case(name.as_bytes()))
        }),
        "MGET" | "DEL" | "UNLINK" | "EXISTS" | "TOUCH" => args.iter().any(|a| a == key),
        "MSET" | "MSETNX" => args.iter().step_by(2).any(|a| a == key),
        "RENAME" | "RENAMENX" | "COPY" | "RPOPLPUSH" | "LMOVE" => {
            args.iter().take(2).any(|a| a == key)
        }
        "GET" | "SET" | "SETEX" | "PSETEX" | "SETNX" | "GETSET" | "GETDEL" | "GETEX" | "APPEND"
        | "STRLEN" | "GETRANGE" | "SETRANGE" | "SUBSTR" | "GETBIT" | "SETBIT" | "BITCOUNT"
        | "INCR" | "INCRBY" | "DECR" | "DECRBY" | "INCRBYFLOAT" | "TYPE" | "TTL" | "PTTL"
        | "EXPIRE" | "PEXPIRE" | "EXPIREAT" | "PEXPIREAT" | "EXPIRETIME" | "PEXPIRETIME"
        | "PERSIST" | "DUMP" | "RESTORE" | "RPUSH" | "LPUSH" | "LSET" | "LRANGE" | "LLEN"
        | "LINDEX" | "LPOP" | "RPOP" | "HGET" | "HSET" | "HGETALL" | "HMGET" | "HMSET" | "HDEL"
        | "HINCRBY" | "SADD" | "SREM" | "SMEMBERS" | "SCARD" | "ZADD" | "ZREM" | "ZRANGE" => {
            args.first().is_some_and(|a| a == key)
        }
        "HSCAN" | "HKEYS" | "HVALS" | "HEXISTS" | "HLEN" | "HSTRLEN" | "HINCRBYFLOAT"
        | "LPUSHX" | "RPUSHX" | "LTRIM" | "LREM" | "LINSERT" | "LPOS" | "SSCAN" | "SISMEMBER"
        | "SMISMEMBER" | "SRANDMEMBER" | "SPOP" | "ZSCAN" | "ZCARD" | "ZCOUNT" | "ZSCORE"
        | "ZMSCORE" | "ZRANK" | "ZREVRANK" | "ZINCRBY" | "ZPOPMIN" | "ZPOPMAX" | "ZLEXCOUNT"
        | "ZREVRANGE" | "PFADD" | "XLEN" | "XRANGE" | "XREVRANGE" | "XADD" | "XACK" | "XDEL"
        | "XTRIM" => args.first().is_some_and(|a| a == key),
        "PING" | "AUTH" | "HELLO" | "SELECT" | "CLIENT" | "QUIT" | "PUBLISH" | "SUBSCRIBE"
        | "UNSUBSCRIBE" | "PSUBSCRIBE" | "PUNSUBSCRIBE" => false,
        // Unknown or key-discovering operations conservatively fence every stream.
        _ => true,
    }
}
