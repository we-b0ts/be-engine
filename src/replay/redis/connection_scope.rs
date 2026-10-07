//! Physical connection pooling is independent of a recorded stateful session.
use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use super::{RecordedExchange, ReplayExchange};

#[derive(Debug, Clone, Copy)]
pub(super) struct TargetConnection {
    pub(super) id: Uuid,
    pub(super) bound: Option<Uuid>,
}

#[cfg(test)]
impl Default for TargetConnection {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            bound: None,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct ConnectionScopes {
    // A whole recorded lane remains bound if any retained command depends on
    // connection state. Detect this during loading, before requests can match.
    stateful: BTreeSet<Uuid>,
    owners: BTreeMap<(Option<String>, Uuid), Uuid>,
}

impl ConnectionScopes {
    pub(super) fn register(&mut self, record: &RecordedExchange, args: &[Vec<u8>]) {
        if record.session_setup || !pool_compatible(&record.command, args) {
            self.stateful.insert(record.connection_id);
        }
    }

    fn requires_binding(&self, exchange: &ReplayExchange) -> bool {
        !exchange.connection_independent && self.stateful.contains(&exchange.record.connection_id)
    }

    pub(super) fn matches(
        &self,
        exchange: &ReplayExchange,
        case_id: Option<&str>,
        target: TargetConnection,
    ) -> bool {
        if exchange.connection_independent {
            return true;
        }
        if target
            .bound
            .is_some_and(|id| id != exchange.record.connection_id)
        {
            return false;
        }
        !self.requires_binding(exchange)
            || self
                .owners
                .get(&(case_id.map(str::to_string), exchange.record.connection_id))
                .is_none_or(|owner| *owner == target.id)
    }

    pub(super) fn claim(
        &mut self,
        exchange: &ReplayExchange,
        case_id: Option<&str>,
        target: TargetConnection,
    ) -> bool {
        let required = self.requires_binding(exchange);
        if required {
            self.owners
                .entry((case_id.map(str::to_string), exchange.record.connection_id))
                .or_insert(target.id);
        }
        required
    }
}

fn pool_compatible(command: &str, args: &[Vec<u8>]) -> bool {
    // Data and script-cache state belongs to the server, not a physical socket.
    // Read/write access classification is insufficient: WAIT, blocking reads,
    // client introspection and SCRIPT DEBUG can depend on the connection.
    // Unknown commands/subcommands stay bound; any retained stateful operation
    // still binds the whole lane, including these pool-compatible commands.
    match command.to_ascii_uppercase().as_str() {
        "EVAL" | "EVALSHA" | "EVAL_RO" | "EVALSHA_RO" => true,
        "SCRIPT" => args.first().is_some_and(|subcommand| {
            ["LOAD", "EXISTS", "FLUSH", "KILL", "HELP"]
                .iter()
                .any(|name| subcommand.eq_ignore_ascii_case(name.as_bytes()))
        }),
        "GET"
        | "MGET"
        | "GETRANGE"
        | "STRLEN"
        | "SUBSTR"
        | "GETBIT"
        | "SET"
        | "SETEX"
        | "PSETEX"
        | "SETNX"
        | "MSET"
        | "MSETNX"
        | "GETSET"
        | "GETDEL"
        | "GETEX"
        | "SETRANGE"
        | "SETBIT"
        | "APPEND"
        | "INCR"
        | "INCRBY"
        | "INCRBYFLOAT"
        | "DECR"
        | "DECRBY"
        | "EXISTS"
        | "TYPE"
        | "TTL"
        | "PTTL"
        | "EXPIRETIME"
        | "PEXPIRETIME"
        | "EXPIRE"
        | "PEXPIRE"
        | "EXPIREAT"
        | "PEXPIREAT"
        | "PERSIST"
        | "DEL"
        | "UNLINK"
        | "TOUCH"
        | "RENAME"
        | "RENAMENX"
        | "COPY"
        | "MOVE"
        | "DUMP"
        | "RESTORE"
        | "KEYS"
        | "SCAN"
        | "RANDOMKEY"
        | "DBSIZE"
        | "HGET"
        | "HMGET"
        | "HGETALL"
        | "HEXISTS"
        | "HLEN"
        | "HKEYS"
        | "HVALS"
        | "HSTRLEN"
        | "HSCAN"
        | "HSET"
        | "HSETNX"
        | "HMSET"
        | "HDEL"
        | "HINCRBY"
        | "HINCRBYFLOAT"
        | "LINDEX"
        | "LLEN"
        | "LPOS"
        | "LRANGE"
        | "LINSERT"
        | "LSET"
        | "LTRIM"
        | "LPUSH"
        | "LPUSHX"
        | "RPUSH"
        | "RPUSHX"
        | "LPOP"
        | "RPOP"
        | "LREM"
        | "LMOVE"
        | "LMPOP"
        | "RPOPLPUSH"
        | "SCARD"
        | "SISMEMBER"
        | "SMISMEMBER"
        | "SMEMBERS"
        | "SRANDMEMBER"
        | "SSCAN"
        | "SDIFF"
        | "SINTER"
        | "SINTERCARD"
        | "SUNION"
        | "SADD"
        | "SREM"
        | "SPOP"
        | "SMOVE"
        | "SDIFFSTORE"
        | "SINTERSTORE"
        | "SUNIONSTORE"
        | "ZCARD"
        | "ZCOUNT"
        | "ZLEXCOUNT"
        | "ZSCORE"
        | "ZMSCORE"
        | "ZRANK"
        | "ZREVRANK"
        | "ZRANGE"
        | "ZRANGEBYLEX"
        | "ZRANGEBYSCORE"
        | "ZREVRANGE"
        | "ZREVRANGEBYLEX"
        | "ZREVRANGEBYSCORE"
        | "ZSCAN"
        | "ZDIFF"
        | "ZINTER"
        | "ZINTERCARD"
        | "ZUNION"
        | "ZADD"
        | "ZINCRBY"
        | "ZREM"
        | "ZPOPMIN"
        | "ZPOPMAX"
        | "ZMPOP"
        | "ZREMRANGEBYLEX"
        | "ZREMRANGEBYRANK"
        | "ZREMRANGEBYSCORE"
        | "ZDIFFSTORE"
        | "ZINTERSTORE"
        | "ZRANGESTORE"
        | "ZUNIONSTORE"
        | "BITCOUNT"
        | "BITPOS"
        | "BITFIELD"
        | "BITFIELD_RO"
        | "BITOP"
        | "LCS"
        | "PFADD"
        | "PFCOUNT"
        | "PFMERGE"
        | "GEOADD"
        | "GEODIST"
        | "GEOHASH"
        | "GEOPOS"
        | "GEOSEARCH"
        | "GEOSEARCHSTORE"
        | "GEORADIUS_RO"
        | "GEORADIUSBYMEMBER_RO"
        | "XLEN"
        | "XPENDING"
        | "XRANGE"
        | "XREVRANGE"
        | "XADD"
        | "XACK"
        | "XDEL"
        | "XTRIM"
        | "XCLAIM"
        | "XAUTOCLAIM"
        | "XSETID" => true,
        "XREAD" | "XREADGROUP" => !args.iter().any(|arg| arg.eq_ignore_ascii_case(b"BLOCK")),
        _ => false,
    }
}
