//! Source-only stream inventory: exact byte order, RESP lengths and read/reset fences.
use super::{
    StorageExchange, is_other_ordinary_exchange, normalized_username as normalize_optional,
    target_matches,
};
use crate::key_access::touches;
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
use traffic_model::{DependencyExchangeOutcome, attribution::DependencyScope as ReplaySource};
use traffic_protocol::connection::Endpoint;

const MAX_BYTES: usize = traffic_value::MAX_VALUE_BYTES;
const MAX_VALUE: usize = traffic_value::MAX_VALUE_BYTES;
const MAX_PIECES: usize = 4096;

#[derive(Debug)]
pub struct StreamProof {
    pub rule: String,
    pub case: String,
    pub target: Endpoint,
    pub database: i64,
    pub username: Option<String>,
    pub resp_version: u8,
    pub key: Vec<u8>,
    pub pieces: Vec<Piece>,
    pub barriers: Vec<(usize, usize)>,
}

#[derive(Debug)]
pub struct Piece {
    pub index: usize,
    pub start: usize,
    pub end: usize,
    pub epoch_start: usize,
    pub base: usize,
}

#[derive(Debug)]
pub struct StreamTrace {
    pub proof: StreamProof,
    pub bytes: Vec<u8>,
}

pub fn prepare<E: StorageExchange>(
    exchanges: &[E],
    case: &str,
    rule: &str,
    seed: &E,
) -> Result<StreamTrace> {
    let key = seed
        .arguments()
        .first()
        .context("append stream Source key missing")?
        .clone();
    let same_database = |e: &E| {
        target_matches(
            &Endpoint {
                host: seed.native_record().target_host.clone(),
                port: seed.native_record().target_port,
            },
            &e.native_record().target_host,
            e.native_record().target_port,
        ) && e.native_record().database == seed.native_record().database
    };
    let same_resource = |e: &E| {
        same_database(e)
            && normalize_optional(e.native_record().username.as_deref())
                == normalize_optional(seed.native_record().username.as_deref())
    };
    ensure!(
        !exchanges.iter().any(|e| same_database(e)
            && !is_other_ordinary_exchange(case, e)
            && (e.source() != ReplaySource::Case
                || e.case_id() != Some(case)
                || normalize_optional(e.native_record().username.as_deref())
                    != normalize_optional(seed.native_record().username.as_deref()))
            && touches(&e.native_record().command, e.arguments(), &key)),
        "append stream key overlaps Global/shared inventory or another Case-local authentication identity"
    );
    let mut timeline = exchanges
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.source() == ReplaySource::Case && e.case_id() == Some(case) && same_resource(e)
        })
        .collect::<Vec<_>>();
    ensure!(
        !timeline.iter().any(|(_, e)| matches!(
            e.native_record().command.as_str(),
            "MULTI" | "EXEC" | "DISCARD" | "WATCH" | "UNWATCH" | "MONITOR"
        )),
        "append stream does not authorize transactional or watched sessions"
    );
    timeline.sort_by_key(|(index, e)| (e.native_record().source_started_at(), *index));
    let mut lanes = BTreeMap::new();
    for (_, e) in &timeline {
        if let Some(previous) =
            lanes.insert(e.native_record().connection_id, e.native_record().sequence)
        {
            ensure!(
                previous < e.native_record().sequence,
                "append stream Source clocks reverse a lane"
            );
        }
    }
    let mut profile = StreamProof {
        rule: rule.into(),
        case: case.into(),
        target: Endpoint {
            host: seed.native_record().target_host.clone(),
            port: seed.native_record().target_port,
        },
        database: seed.native_record().database,
        username: seed.native_record().username.clone(),
        resp_version: seed.native_record().resp_version,
        key,
        pieces: vec![],
        barriers: vec![],
    };
    let mut stream_bytes = Vec::new();
    let mut base = None;
    let mut epoch_start = 0_usize;
    let mut initial_known = true;
    let mut last_access: Option<&E> = None;
    for (index, exchange) in timeline {
        if !touches(
            &exchange.native_record().command,
            exchange.arguments(),
            &profile.key,
        ) {
            continue;
        }
        if !matches!(
            exchange.native_record().command.as_str(),
            "EXPIRE" | "PEXPIRE"
        ) {
            if let Some(previous) = last_access {
                ensure!(
                    previous.native_record().connection_id
                        == exchange.native_record().connection_id
                        || previous
                            .native_record()
                            .timestamp
                            .zip(exchange.native_record().earliest_start())
                            .is_some_and(|(end, start)| end <= start),
                    "append stream Source accesses overlap or lack causal clocks"
                );
            }
            last_access = Some(exchange);
        }
        let offset = stream_bytes.len();
        if exchange.native_record().command == "APPEND" {
            ensure!(
                initial_known,
                "append stream follows an unsupported mutation"
            );
            ensure!(
                !exchange.explicitly_shared()
                    && exchange.native_record().cache_snapshot_rule.is_none()
                    && !exchange.native_record().cache_snapshot_hit
                    && !exchange.native_record().session_setup
                    && exchange.native_record().run_owner_kind().is_none()
                    && exchange.native_record().resp_version == profile.resp_version,
                "append stream requires ordinary Case exchanges"
            );
            ensure!(
                exchange.native_record().outcome == DependencyExchangeOutcome::Response
                    && exchange.native_record().response_kind == "integer"
                    && exchange.arguments().len() == 2,
                "append stream requires successful two-argument APPEND"
            );
            let bytes = &exchange.arguments()[1];
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_VALUE,
                "append stream Source chunk exceeds bounds"
            );
            ensure!(
                profile.pieces.len() < MAX_PIECES && offset + bytes.len() <= MAX_BYTES,
                "append stream Source inventory exceeds bounds"
            );
            let returned = integer(&exchange.response_bytes()?)?;
            let appended = (offset - epoch_start)
                .checked_add(bytes.len())
                .context("append stream Source length overflow")?;
            let base = match base {
                Some(base) => base,
                None => {
                    // APPEND proves its own increment and resulting length;
                    // the preexisting prefix bytes are outside this Case.
                    let initial = returned
                        .checked_sub(appended)
                        .context("APPEND response is shorter than the appended Source bytes")?;
                    base = Some(initial);
                    initial
                }
            };
            let expected = base
                .checked_add(appended)
                .context("append stream Source length overflow")?;
            ensure!(
                returned == expected,
                "APPEND response does not prove the cumulative Source byte length"
            );
            stream_bytes.extend_from_slice(bytes);
            profile.pieces.push(Piece {
                index,
                start: offset,
                end: offset + bytes.len(),
                epoch_start,
                base,
            });
            continue;
        }
        // A successful fixed-argument expiry refresh is still matched and consumed
        // by its ordinary native owner. It does not observe the string's contents.
        if matches!(
            exchange.native_record().command.as_str(),
            "EXPIRE" | "PEXPIRE"
        ) {
            ensure!(
                exchange.arguments().len() == 2
                    && exchange.native_record().outcome == DependencyExchangeOutcome::Response
                    && exchange.native_record().response_kind == "integer"
                    && exchange.arguments()[1].iter().all(u8::is_ascii_digit)
                    && !exchange.arguments()[1].is_empty()
                    && std::str::from_utf8(&exchange.arguments()[1])?.parse::<u64>()? > 0
                    && integer(&exchange.response_bytes()?)? == 1,
                "append stream supports only successful unconditional positive expiry refreshes"
            );
            continue;
        }
        profile.barriers.push((index, offset));
        let response = exchange.response_bytes()?;
        let success = exchange.native_record().outcome == DependencyExchangeOutcome::Response;
        match exchange.native_record().command.as_str() {
            "DEL" | "UNLINK" if success && integer(&response).is_ok() => {
                base = Some(0);
                epoch_start = offset;
                initial_known = true;
            }
            "SET" | "SETEX" | "PSETEX" if success && response == b"+OK\r\n" => {
                let value = if exchange.native_record().command == "SET" {
                    1
                } else {
                    2
                };
                base = Some(
                    exchange
                        .arguments()
                        .get(value)
                        .context("append stream reset lacks value")?
                        .len(),
                );
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
    Ok(StreamTrace {
        proof: profile,
        bytes: stream_bytes,
    })
}

fn integer(bytes: &[u8]) -> Result<usize> {
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
