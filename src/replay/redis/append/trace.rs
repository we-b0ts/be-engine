//! Source-only stream inventory: exact byte order, RESP lengths and read/reset fences.
use super::*;

pub(super) fn prepare(
    exchanges: &[ReplayExchange],
    case: &str,
    rule: &str,
    seed: &ReplayExchange,
) -> Result<Profile> {
    let key = seed
        .args
        .first()
        .context("append stream Source key missing")?
        .clone();
    let same_database = |e: &ReplayExchange| {
        target_matches(
            &TargetKey {
                host: seed.record.target_host.clone(),
                port: seed.record.target_port,
            },
            &e.record.target_host,
            e.record.target_port,
        ) && e.record.database == seed.record.database
    };
    let same_resource = |e: &ReplayExchange| {
        same_database(e)
            && normalize_optional(e.record.username.as_deref())
                == normalize_optional(seed.record.username.as_deref())
    };
    ensure!(
        !exchanges.iter().any(|e| same_database(e)
            && (e.case_id.as_deref() != Some(case)
                || normalize_optional(e.record.username.as_deref())
                    != normalize_optional(seed.record.username.as_deref()))
            && touches(&e.record.command, &e.args, &key)),
        "append stream key overlaps another Case or Global inventory"
    );
    let mut timeline = exchanges
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case) && same_resource(e)
        })
        .collect::<Vec<_>>();
    ensure!(
        !timeline.iter().any(|(_, e)| matches!(
            e.record.command.as_str(),
            "MULTI" | "EXEC" | "DISCARD" | "WATCH" | "UNWATCH" | "MONITOR"
        )),
        "append stream does not authorize transactional or watched sessions"
    );
    timeline.sort_by_key(|(index, e)| (e.record.started_at(), *index));
    let mut lanes = BTreeMap::new();
    for (_, e) in &timeline {
        if let Some(previous) = lanes.insert(e.record.connection_id, e.record.sequence) {
            ensure!(
                previous < e.record.sequence,
                "append stream Source clocks reverse a lane"
            );
        }
    }
    let mut profile = Profile {
        rule: rule.into(),
        case: case.into(),
        target: TargetKey {
            host: seed.record.target_host.clone(),
            port: seed.record.target_port,
        },
        database: seed.record.database,
        username: seed.record.username.clone(),
        resp_version: seed.record.resp_version,
        key,
        bytes: vec![],
        pieces: vec![],
        barriers: vec![],
        target_key: None,
        reserved: 0,
        delivered: 0,
        completed: BTreeMap::new(),
        in_flight: BTreeMap::new(),
        failed: false,
    };
    let mut base = 0_usize;
    let mut epoch_start = 0_usize;
    let mut initial_known = true;
    let mut last_access: Option<&ReplayExchange> = None;
    for (index, exchange) in timeline {
        if !touches(&exchange.record.command, &exchange.args, &profile.key) {
            continue;
        }
        if !matches!(exchange.record.command.as_str(), "EXPIRE" | "PEXPIRE") {
            if let Some(previous) = last_access {
                ensure!(
                    previous.record.connection_id == exchange.record.connection_id
                        || previous
                            .record
                            .timestamp
                            .zip(exchange.record.earliest_start())
                            .is_some_and(|(end, start)| end <= start),
                    "append stream Source accesses overlap or lack causal clocks"
                );
            }
            last_access = Some(exchange);
        }
        let offset = profile.bytes.len();
        if exchange.record.command == "APPEND" {
            ensure!(
                initial_known,
                "append stream follows an unsupported mutation"
            );
            ensure!(
                exchange.shared_rule_id.is_none()
                    && !exchange.reusable_snapshot
                    && exchange.record.cache_snapshot_rule.is_none()
                    && !exchange.record.cache_snapshot_hit
                    && !exchange.record.session_setup
                    && exchange.record.global_dependency_reason.is_none()
                    && exchange.record.resp_version == profile.resp_version,
                "append stream requires ordinary Case exchanges"
            );
            ensure!(
                exchange.record.outcome == DependencyExchangeOutcome::Response
                    && exchange.record.response_kind == "integer"
                    && exchange.args.len() == 2,
                "append stream requires successful two-argument APPEND"
            );
            let bytes = &exchange.args[1];
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_VALUE,
                "append stream Source chunk exceeds bounds"
            );
            ensure!(
                profile.pieces.len() < MAX_PIECES && offset + bytes.len() <= MAX_BYTES,
                "append stream Source inventory exceeds bounds"
            );
            let expected = base
                .checked_add(offset - epoch_start)
                .and_then(|n| n.checked_add(bytes.len()))
                .context("append stream Source length overflow")?;
            ensure!(
                integer(&exchange.response_bytes()?)? == expected,
                "APPEND response does not prove the cumulative Source byte length"
            );
            profile.bytes.extend_from_slice(bytes);
            profile.pieces.push(Piece {
                index,
                start: offset,
                end: profile.bytes.len(),
                epoch_start,
                base,
            });
            continue;
        }
        // A successful fixed-argument expiry refresh is still matched and consumed
        // by its ordinary native owner. It does not observe the string's contents.
        if matches!(exchange.record.command.as_str(), "EXPIRE" | "PEXPIRE") {
            ensure!(
                exchange.args.len() == 2
                    && exchange.record.outcome == DependencyExchangeOutcome::Response
                    && exchange.record.response_kind == "integer"
                    && exchange.args[1].iter().all(u8::is_ascii_digit)
                    && !exchange.args[1].is_empty()
                    && std::str::from_utf8(&exchange.args[1])?.parse::<u64>()? > 0
                    && integer(&exchange.response_bytes()?)? == 1,
                "append stream supports only successful unconditional positive expiry refreshes"
            );
            continue;
        }
        profile.barriers.push((index, offset));
        let response = exchange.response_bytes()?;
        let success = exchange.record.outcome == DependencyExchangeOutcome::Response;
        match exchange.record.command.as_str() {
            "DEL" | "UNLINK" if success && integer(&response).is_ok() => {
                base = 0;
                epoch_start = offset;
                initial_known = true;
            }
            "SET" | "SETEX" | "PSETEX" if success && response == b"+OK\r\n" => {
                let value = if exchange.record.command == "SET" {
                    1
                } else {
                    2
                };
                base = exchange
                    .args
                    .get(value)
                    .context("append stream reset lacks value")?
                    .len();
                epoch_start = offset;
                initial_known = true;
            }
            // Read fences never authorize changed reads or skip their responses.
            "GET" | "MGET" | "STRLEN" | "GETRANGE" | "SUBSTR" | "GETBIT" | "BITCOUNT"
            | "EXISTS" | "TYPE" | "TTL" | "PTTL" | "EXPIRETIME" | "PEXPIRETIME" | "DUMP" => (),
            _ => initial_known = false,
        }
    }
    ensure!(
        !profile.pieces.is_empty(),
        "append stream lacks a positive Source write"
    );
    Ok(profile)
}

pub(super) fn integer(bytes: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(bytes)?
        .strip_prefix(':')
        .and_then(|s| s.strip_suffix("\r\n"))
        .context("append stream requires a RESP integer")?;
    let value: usize = text.parse()?;
    ensure!(
        value.to_string() == text,
        "append stream integer is not canonical"
    );
    Ok(value)
}

pub(super) fn touches(command: &str, args: &[Vec<u8>], key: &[u8]) -> bool {
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
