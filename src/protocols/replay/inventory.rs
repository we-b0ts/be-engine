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
    let mysql_keys = connection_keys(references, "mysql")?;
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

    references
        .iter()
        .map(|reference| {
            let (inventory, index) = match reference.protocol() {
                "mysql" => ("mysql", mysql[&connection(reference)?]),

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
        "mysql" => state.protocol_data().mysql.exchange_status(index),

        _ => None,
    }
}

pub(super) fn permits_cancelled_omission(_: &State, _: ProtocolExchange) -> bool {
    false
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
        _ => false,
    }
}

pub(super) fn shared_initialization(
    _: &State,
    _: ProtocolExchange,
    _: &crate::recorder::async_api::CompletionRequirements,
) -> bool {
    false
}
