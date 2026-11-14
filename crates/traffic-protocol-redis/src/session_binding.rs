//! Native physical-session eligibility projected from immutable recorded facts.
use std::collections::BTreeMap;
use traffic_model::attribution::DependencyScope as ReplaySource;
use uuid::Uuid;

pub trait RecordedSession {
    fn connection_id(&self) -> Uuid;
    fn sequence(&self) -> u64;
    fn command(&self) -> &str;
    fn session_setup(&self) -> bool;
}

pub trait SessionExchange {
    type Record: RecordedSession;
    fn record(&self) -> &Self::Record;
    fn source(&self) -> ReplaySource;
    fn case_id(&self) -> Option<&str>;
    fn connection_independent(&self) -> bool;
}

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy)]
pub struct TargetConnection {
    pub id: Uuid,
    pub bound: Option<Uuid>,
}

impl Default for TargetConnection {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            bound: None,
        }
    }
}

#[derive(Debug, Default)]
struct LaneState {
    whole_lane: bool,
    first_subscribe: Option<u64>,
    first_unsubscribe: Option<u64>,
}

impl LaneState {
    fn register(&mut self, record: &impl RecordedSession) {
        let first = match record.command().to_ascii_uppercase().as_str() {
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" if !record.session_setup() => {
                &mut self.first_subscribe
            }
            "UNSUBSCRIBE" | "PUNSUBSCRIBE" | "SUNSUBSCRIBE" if !record.session_setup() => {
                &mut self.first_unsubscribe
            }
            _ => {
                self.whole_lane = true;
                return;
            }
        };
        *first = Some(first.map_or(record.sequence(), |sequence| {
            sequence.min(record.sequence())
        }));
    }

    fn contains(&self, sequence: u64) -> bool {
        // A pool may lend an ordinary connection to a later subscriber. Only
        // its subscription suffix owns the socket. Unknown state, explicit
        // setup and an unsubscribe without a preceding subscribe stay strict.
        self.whole_lane
            || self.first_subscribe.is_none_or(|start| {
                self.first_unsubscribe.is_some_and(|end| end < start) || sequence >= start
            })
    }
}

#[derive(Debug, Default)]
pub struct ConnectionScopes {
    // Ordinary Case commands bind only their Case's lane. Global commands and
    // explicit session_setup retain a connection-wide boundary, even when a
    // setup record carries a Case origin.
    stateful_global: BTreeMap<Uuid, LaneState>,
    stateful_cases: BTreeMap<String, BTreeMap<Uuid, LaneState>>,
    owners: BTreeMap<(Option<String>, Uuid), Uuid>,
}

impl ConnectionScopes {
    pub fn is_stateful(&self, exchange: &impl SessionExchange) -> bool {
        self.stateful_global
            .get(&exchange.record().connection_id())
            .is_some_and(|lane| lane.contains(exchange.record().sequence()))
            || (exchange.source() == ReplaySource::Case
                && exchange.case_id().is_some_and(|case| {
                    self.stateful_cases
                        .get(case)
                        .and_then(|lanes| lanes.get(&exchange.record().connection_id()))
                        .is_some_and(|lane| lane.contains(exchange.record().sequence()))
                }))
    }

    pub fn register(
        &mut self,
        record: &impl RecordedSession,
        args: &[Vec<u8>],
        source: ReplaySource,
        case_id: Option<&str>,
    ) {
        if record.session_setup() || !pool_compatible(record.command(), args) {
            let lanes = if !record.session_setup()
                && source == ReplaySource::Case
                && let Some(case) = case_id
            {
                self.stateful_cases.entry(case.into()).or_default()
            } else {
                &mut self.stateful_global
            };
            lanes
                .entry(record.connection_id())
                .or_default()
                .register(record);
        }
    }

    fn requires_binding(&self, exchange: &impl SessionExchange) -> bool {
        !exchange.connection_independent() && self.is_stateful(exchange)
    }

    pub fn matches(
        &self,
        exchange: &impl SessionExchange,
        case_id: Option<&str>,
        target: TargetConnection,
    ) -> bool {
        if exchange.connection_independent() {
            return true;
        }
        if target
            .bound
            .is_some_and(|id| id != exchange.record().connection_id())
        {
            return false;
        }
        !self.requires_binding(exchange)
            || self
                .owners
                .get(&(
                    case_id.map(str::to_string),
                    exchange.record().connection_id(),
                ))
                .is_none_or(|owner| *owner == target.id)
    }

    pub fn bind(
        &mut self,
        exchange: &impl SessionExchange,
        case_id: Option<&str>,
        target: TargetConnection,
    ) -> bool {
        let required = self.requires_binding(exchange);
        if required {
            self.owners
                .entry((
                    case_id.map(str::to_string),
                    exchange.record().connection_id(),
                ))
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
        "PUBLISH"
        | "GET"
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
