use traffic_protocol::connection::Operation as OperationClass;

use super::RedisCommand;

pub fn classify_command(command: &RedisCommand) -> OperationClass {
    let name = command.name.as_str();
    match name {
        "AUTH" | "HELLO" | "SELECT" | "PING" | "QUIT" | "RESET" => OperationClass::Session,
        _ if crate::is_pubsub_command(name) => OperationClass::Session,
        "CLIENT" => classify_subcommand(
            command,
            &["GETNAME", "ID", "INFO", "LIST"],
            &[
                "CACHING", "NO-EVICT", "NO-TOUCH", "REPLY", "SETNAME", "SETINFO", "TRACKING",
            ],
            &["KILL", "PAUSE", "UNBLOCK", "UNPAUSE"],
        ),
        "CONFIG" => classify_subcommand(
            command,
            &["GET", "HELP"],
            &[],
            &["SET", "RESETSTAT", "REWRITE"],
        ),
        "ACL" => classify_subcommand(
            command,
            &[
                "CAT", "DRYRUN", "GENPASS", "GETUSER", "HELP", "LIST", "LOG", "USERS", "WHOAMI",
            ],
            &[],
            &["DELUSER", "LOAD", "SAVE", "SETUSER"],
        ),
        "SCRIPT" => classify_subcommand(
            command,
            &["EXISTS", "HELP"],
            &[],
            &["DEBUG", "FLUSH", "KILL", "LOAD"],
        ),
        "FUNCTION" => classify_subcommand(
            command,
            &["DUMP", "HELP", "LIST", "STATS"],
            &[],
            &["DELETE", "FLUSH", "KILL", "LOAD", "RESTORE"],
        ),
        "CLUSTER" => classify_subcommand(
            command,
            &[
                "COUNT-FAILURE-REPORTS",
                "COUNTKEYSINSLOT",
                "GETKEYSINSLOT",
                "HELP",
                "INFO",
                "KEYSLOT",
                "LINKS",
                "MYID",
                "MYSHARDID",
                "NODES",
                "SHARDS",
                "SLOTS",
            ],
            &[],
            &[
                "ADDSLOTS",
                "ADDSLOTSRANGE",
                "BUMPEPOCH",
                "DELSLOTS",
                "DELSLOTSRANGE",
                "FAILOVER",
                "FLUSHSLOTS",
                "FORGET",
                "MEET",
                "REPLICATE",
                "RESET",
                "SAVECONFIG",
                "SET-CONFIG-EPOCH",
                "SETSLOT",
            ],
        ),
        "MEMORY" => classify_subcommand(
            command,
            &["DOCTOR", "HELP", "MALLOC-STATS", "STATS", "USAGE"],
            &[],
            &["PURGE"],
        ),
        "LATENCY" => classify_subcommand(
            command,
            &["DOCTOR", "GRAPH", "HELP", "HISTORY", "LATEST"],
            &[],
            &["RESET"],
        ),
        "EVAL_RO" | "EVALSHA_RO" | "FCALL_RO" => OperationClass::Read,
        "EVAL" | "EVALSHA" | "FCALL" => OperationClass::Write,
        "GET"
        | "MGET"
        | "GETRANGE"
        | "STRLEN"
        | "SUBSTR"
        | "EXISTS"
        | "TYPE"
        | "TTL"
        | "PTTL"
        | "EXPIRETIME"
        | "PEXPIRETIME"
        | "DUMP"
        | "KEYS"
        | "SCAN"
        | "RANDOMKEY"
        | "HGET"
        | "HMGET"
        | "HGETALL"
        | "HEXISTS"
        | "HLEN"
        | "HKEYS"
        | "HVALS"
        | "HSTRLEN"
        | "HSCAN"
        | "LINDEX"
        | "LLEN"
        | "LPOS"
        | "LRANGE"
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
        | "PFCOUNT"
        | "GEODIST"
        | "GEOHASH"
        | "GEOPOS"
        | "GEOSEARCH"
        | "GEORADIUS_RO"
        | "GEORADIUSBYMEMBER_RO"
        | "XINFO"
        | "XLEN"
        | "XPENDING"
        | "XRANGE"
        | "XREVRANGE"
        | "XREAD"
        | "XREADGROUP"
        | "BITCOUNT"
        | "BITPOS"
        | "GETBIT"
        | "LCS"
        | "SORT_RO"
        | "DBSIZE"
        | "TIME"
        | "LASTSAVE"
        | "INFO"
        | "ROLE"
        | "COMMAND"
        | "OBJECT"
        | "PUBSUB"
        | "SLOWLOG"
        | "LOLWUT"
        | "WAIT"
        | "WAITAOF" => OperationClass::Read,
        "APPEND" | "DECR" | "DECRBY" | "GETDEL" | "GETEX" | "INCR" | "INCRBY" | "INCRBYFLOAT"
        | "MSET" | "MSETNX" | "PSETEX" | "SET" | "SETEX" | "SETNX" | "SETRANGE" | "COPY"
        | "DEL" | "EXPIRE" | "EXPIREAT" | "PEXPIRE" | "PEXPIREAT" | "PERSIST" | "MOVE"
        | "RENAME" | "RENAMENX" | "RESTORE" | "MIGRATE" | "TOUCH" | "HDEL" | "HINCRBY"
        | "HINCRBYFLOAT" | "HMSET" | "HSET" | "HSETNX" | "BLMOVE" | "BLMPOP" | "BLPOP"
        | "BRPOP" | "BRPOPLPUSH" | "LINSERT" | "LMOVE" | "LMPOP" | "LPOP" | "LPUSH" | "LPUSHX"
        | "LREM" | "LSET" | "LTRIM" | "RPOP" | "RPOPLPUSH" | "RPUSH" | "RPUSHX" | "SADD"
        | "SDIFFSTORE" | "SINTERSTORE" | "SMOVE" | "SPOP" | "SREM" | "SUNIONSTORE" | "ZADD"
        | "ZDIFFSTORE" | "ZINCRBY" | "ZINTERSTORE" | "ZMPOP" | "ZPOPMAX" | "ZPOPMIN"
        | "ZRANGESTORE" | "ZREM" | "ZREMRANGEBYLEX" | "ZREMRANGEBYRANK" | "ZREMRANGEBYSCORE"
        | "ZUNIONSTORE" | "PFADD" | "PFMERGE" | "GEOADD" | "GEOSEARCHSTORE" | "XACK" | "XADD"
        | "XAUTOCLAIM" | "XCLAIM" | "XDEL" | "XGROUP" | "XSETID" | "XTRIM" | "BITFIELD"
        | "BITOP" | "SETBIT" | "PUBLISH" | "SPUBLISH" | "FLUSHALL" | "FLUSHDB" | "SWAPDB"
        | "BGSAVE" | "BGREWRITEAOF" | "SAVE" | "SHUTDOWN" | "REPLICAOF" | "SLAVEOF" | "MODULE" => {
            OperationClass::Write
        }
        "SORT" => {
            if command
                .args
                .iter()
                .any(|arg| arg.eq_ignore_ascii_case(b"STORE"))
            {
                OperationClass::Write
            } else {
                OperationClass::Read
            }
        }
        _ => OperationClass::Unknown,
    }
}

fn classify_subcommand(
    command: &RedisCommand,
    reads: &[&str],
    sessions: &[&str],
    writes: &[&str],
) -> OperationClass {
    let Some(subcommand) = command.args.first() else {
        return OperationClass::Unknown;
    };
    if reads
        .iter()
        .any(|candidate| subcommand.eq_ignore_ascii_case(candidate.as_bytes()))
    {
        OperationClass::Read
    } else if sessions
        .iter()
        .any(|candidate| subcommand.eq_ignore_ascii_case(candidate.as_bytes()))
    {
        OperationClass::Session
    } else if writes
        .iter()
        .any(|candidate| subcommand.eq_ignore_ascii_case(candidate.as_bytes()))
    {
        OperationClass::Write
    } else {
        OperationClass::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(name: &str, args: &[&str]) -> RedisCommand {
        RedisCommand {
            name: name.to_string(),
            args: args.iter().map(|arg| arg.as_bytes().to_vec()).collect(),
        }
    }

    #[test]
    fn classifies_core_and_subcommands() {
        assert_eq!(
            classify_command(&command("GET", &["key"])),
            OperationClass::Read
        );
        assert_eq!(
            classify_command(&command("SET", &["key", "v"])),
            OperationClass::Write
        );
        assert_eq!(
            classify_command(&command("AUTH", &["secret"])),
            OperationClass::Session
        );
        assert_eq!(
            classify_command(&command("CLIENT", &["TRACKING", "ON"])),
            OperationClass::Session
        );
        assert_eq!(
            classify_command(&command("CONFIG", &["GET", "*"])),
            OperationClass::Read
        );
        assert_eq!(
            classify_command(&command("CONFIG", &["SET", "x", "y"])),
            OperationClass::Write
        );
        assert_eq!(
            classify_command(&command("MODULE.CUSTOM", &[])),
            OperationClass::Unknown
        );
    }

    #[test]
    fn classifies_commands_with_read_and_write_forms() {
        assert_eq!(
            classify_command(&command("SORT", &["key"])),
            OperationClass::Read
        );
        assert_eq!(
            classify_command(&command("SORT", &["key", "STORE", "out"])),
            OperationClass::Write
        );
        assert_eq!(
            classify_command(&command("EVAL_RO", &[])),
            OperationClass::Read
        );
        assert_eq!(
            classify_command(&command("EVAL", &[])),
            OperationClass::Write
        );
    }
}
