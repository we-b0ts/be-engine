//! Prove finite absent reads against complete scoped native Redis inventory.
use super::{
    StorageExchange, is_other_ordinary_exchange, normalized_username as normalize_optional,
    target_matches,
};
use crate::session_binding::ConnectionScopes;
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use traffic_model::{DependencyExchangeOutcome, attribution::DependencyScope};
use traffic_protocol::connection::Endpoint;

#[derive(Debug)]
pub struct ReadCommutationProof {
    pub case: String,
    pub target: Endpoint,
    pub database: i64,
    pub key: Vec<u8>,
    pub rule: String,
    pub reads: Vec<usize>,
}

pub fn prove_read_commutation<E: StorageExchange>(
    exchanges: &[E],
    scopes: &ConnectionScopes,
    case: &str,
    rule: &str,
    seed: &E,
) -> Result<ReadCommutationProof> {
    let mut profile = ReadCommutationProof {
        case: case.into(),
        target: Endpoint {
            host: seed.native_record().target_host.clone(),
            port: seed.native_record().target_port,
        },
        database: seed.native_record().database,
        key: seed
            .arguments()
            .first()
            .context("read commutation Source key missing")?
            .clone(),
        rule: rule.into(),
        reads: Vec::new(),
    };
    let mut cleanups = Vec::new();
    for (index, exchange) in exchanges.iter().enumerate().filter(|(_, e)| {
        e.native_record().database == profile.database
            && target_matches(
                &profile.target,
                &e.native_record().target_host,
                e.native_record().target_port,
            )
            && crate::key_access::touches(&e.native_record().command, e.arguments(), &profile.key)
    }) {
        if is_other_ordinary_exchange(case, exchange) {
            continue;
        }
        ensure!(
            exchange.source() == DependencyScope::Case && exchange.case_id() == Some(case),
            "read commutation key overlaps Global or shared inventory"
        );
        ensure!(
            !exchange.explicitly_shared()
                && exchange.native_record().cache_snapshot_rule.is_none()
                && !exchange.native_record().cache_snapshot_hit
                && !exchange.native_record().session_setup
                && exchange.native_record().run_owner_kind().is_none()
                && exchange.native_record().outcome == DependencyExchangeOutcome::Response
                && exchange.native_record().resp_version == seed.native_record().resp_version
                && normalize_optional(exchange.native_record().username.as_deref())
                    == normalize_optional(seed.native_record().username.as_deref()),
            "read commutation requires ordinary successful Case exchanges with one protocol/user"
        );
        let response = exchange.response_bytes()?;
        match exchange.native_record().command.as_str() {
            "GET" => {
                ensure!(
                    exchange.arguments() == [profile.key.clone()],
                    "read commutation requires single-key observations"
                );
                ensure!(
                    !scopes.is_stateful(exchange),
                    "read commutation cannot relax stateful or transactional Source lanes"
                );
                ensure!(
                    response == b"$-1\r\n",
                    "read commutation requires unchanged nil GET responses"
                );
                profile.reads.push(index);
            }
            "DEL" => cleanups.push((exchange, response)),
            _ => anyhow::bail!("read commutation key has a mutation or unsupported observation"),
        }
    }
    ensure!(
        !profile.reads.is_empty(),
        "read commutation lacks a Source observation"
    );
    for (cleanup, response) in cleanups {
        validate_cleanup(exchanges, &profile, cleanup, &response)?;
    }
    Ok(profile)
}

fn validate_cleanup<E: StorageExchange>(
    exchanges: &[E],
    profile: &ReadCommutationProof,
    cleanup: &E,
    response: &[u8],
) -> Result<()> {
    if cleanup.arguments() == [profile.key.clone()] {
        ensure!(
            response == b":0\r\n",
            "read commutation cleanup changed the key"
        );
        return Ok(());
    }
    // A final multi-key DEL may remove other keys. The selected key must
    // already have been observed absent before cleanup, with no writer in the
    // complete scoped inventory. Keep the DEL itself finite and lane-ordered.
    ensure!(
        profile.reads.iter().all(|&index| {
            let read = &exchanges[index];
            if read.native_record().connection_id == cleanup.native_record().connection_id {
                read.native_record().sequence < cleanup.native_record().sequence
            } else {
                read.native_record()
                    .timestamp
                    .zip(cleanup.native_record().earliest_start())
                    .is_some_and(|(end, start)| end <= start)
            }
        }),
        "read commutation multi-key cleanup must follow every nil observation"
    );
    let other_keys = cleanup
        .arguments()
        .iter()
        .filter(|key| **key != profile.key)
        .collect::<BTreeSet<_>>()
        .len();
    let removed = response
        .strip_prefix(b":")
        .and_then(|value| value.strip_suffix(b"\r\n"))
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<usize>().ok());
    ensure!(
        other_keys > 0 && removed.is_some_and(|removed| removed <= other_keys),
        "read commutation multi-key cleanup count cannot include the absent key"
    );
    Ok(())
}
