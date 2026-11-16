//! Native inventories resolve original references and project actual delivery state.
use super::*;
use crate::replay::{ProtocolExchange, RecordedReference, ReplayExchangeStatus};
use anyhow::{bail, ensure};
use serde::Deserialize;
use std::collections::BTreeSet;
use traffic_replay::ReplaySource;
use uuid::Uuid;

type State = RuntimeState<ReplayProtocols>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionIdentity {
    connection_id: Uuid,
    sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeIdentity {
    exchange_id: Uuid,
}

fn connection(reference: &RecordedReference) -> Result<(Uuid, u64)> {
    let identity: ConnectionIdentity = reference.identity()?;
    Ok((identity.connection_id, identity.sequence))
}

fn exchange(reference: &RecordedReference) -> Result<Uuid> {
    Ok(reference.identity::<ExchangeIdentity>()?.exchange_id)
}

fn connection_keys(
    references: &[RecordedReference],
    protocol: &str,
) -> Result<BTreeSet<(Uuid, u64)>> {
    references
        .iter()
        .filter(|reference| reference.protocol() == protocol)
        .map(connection)
        .collect()
}

pub(super) fn resolve(
    state: &State,
    case: &str,
    references: &[RecordedReference],
) -> Result<Vec<ProtocolExchange>> {
    let redis_keys = connection_keys(references, "redis")?;
    let redis = state
        .protocol_data()
        .redis
        .case_wire_exchange_indices(case, &redis_keys)?;
    let mysql_keys = connection_keys(references, "mysql")?;
    let http_keys = references
        .iter()
        .filter(|reference| reference.protocol() == "http")
        .map(exchange)
        .collect::<Result<_>>()?;
    let http = state.http_case_exchange_indices(case, &http_keys)?;
    let mut mysql = BTreeMap::new();
    for (index, exchange) in state.protocol_data().mysql.exchanges.iter().enumerate() {
        let Some(key) = exchange
            .record
            .connection_id
            .zip(exchange.record.query_sequence)
        else {
            continue;
        };
        if exchange.source == ReplaySource::Case
            && exchange.case_id.as_deref() == Some(case)
            && mysql_keys.contains(&key)
        {
            ensure!(
                mysql.insert(key, index).is_none(),
                "dependency-tail MySQL reference is ambiguous in its Case semantic dependencies"
            );
        }
    }
    ensure!(
        mysql.len() == mysql_keys.len(),
        "dependency-tail MySQL reference is absent from its Case semantic dependencies"
    );
    let rpc_pushes = state.protocol_data().redis.pubsub.finite_rpc_pushes(case)?;

    references
        .iter()
        .map(|reference| {
            let (inventory, index) = match reference.protocol() {
                "redis" => ("redis", redis[&connection(reference)?]),
                "mysql" => ("mysql", mysql[&connection(reference)?]),
                "http" => ("http", http[&exchange(reference)?]),
                "redis_rpc_push" => (
                    "redis_rpc_push",
                    *rpc_pushes
                        .get(&connection(reference)?)
                        .context("finite Redis callback reference is absent from Case inventory")?,
                ),

                _ => bail!("finite native reference has no installed inventory owner"),
            };
            Ok(ProtocolExchange {
                inventory: ProtocolId::new(inventory),
                index,
            })
        })
        .collect()
}

pub(super) fn status(state: &State, exchange: ProtocolExchange) -> Option<ReplayExchangeStatus> {
    let index = exchange.index;
    match exchange.inventory.as_str() {
        "redis" => state.protocol_data().redis.exchange_status(index),
        "redis_rpc_push" => state
            .protocol_data()
            .redis
            .pubsub
            .finite_rpc_push_status(index),
        "mysql" => state.protocol_data().mysql.exchange_status(index),
        "http" => state.http_exchange_status(index),

        _ => None,
    }
}

pub(super) fn permits_cancelled_omission(state: &State, exchange: ProtocolExchange) -> bool {
    match exchange.inventory.as_str() {
        "redis" => state
            .protocol_data()
            .redis
            .permits_cancelled_append_omission(exchange.index),
        "http" => state.permits_cancelled_http_omission(exchange.index),
        _ => false,
    }
}

pub(super) fn permits_unstarted_omission(
    state: &State,
    exchange: ProtocolExchange,
    shared_initialization: bool,
    strict_reference: bool,
) -> bool {
    match exchange.inventory.as_str() {
        "mysql" => state
            .protocol_data()
            .mysql
            .permits_unstarted_omission(exchange.index),
        "http" => {
            !strict_reference
                && shared_initialization
                && state.http_exchange_status(exchange.index)
                    == Some(ReplayExchangeStatus::Available)
        }
        _ => false,
    }
}

pub(super) fn shared_initialization(
    state: &State,
    exchange: ProtocolExchange,
    completion: &crate::recorder::async_api::CompletionRequirements,
) -> bool {
    exchange.inventory.as_str() == "http"
        && state.http_shared_initialization(
            exchange.index,
            completion
                .get::<Vec<crate::policy::AsyncHttpEnd>>()
                .map_or(&[], Vec::as_slice),
        )
}
