//! Resolve exact Case-scoped native references without claiming or consuming them.
use super::{
    DependencyAdapter, ExchangeHandle, NativeDependencyAdapter, RecordedReference, contract,
};
use crate::replay::{ReplaySource, ReplayState};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::replay) fn resolve_case<T>(
    state: &ReplayState,
    case_id: &str,
    references: &[RecordedReference],
    project: impl Fn(RecordedReference, ExchangeHandle) -> T,
) -> Result<Vec<T>> {
    let redis_keys = references
        .iter()
        .filter_map(|reference| match reference {
            RecordedReference::Redis {
                connection_id,
                sequence,
            } => Some((*connection_id, *sequence)),
            _ => None,
        })
        .collect();
    let redis = state
        .redis
        .case_wire_exchange_indices(case_id, &redis_keys)?;
    let mysql_keys: BTreeSet<_> = references
        .iter()
        .filter_map(|reference| match reference {
            RecordedReference::Mysql {
                connection_id,
                sequence,
            } => Some((*connection_id, *sequence)),
            _ => None,
        })
        .collect();
    let http_keys = references
        .iter()
        .filter_map(|reference| match reference {
            RecordedReference::Http { exchange_id } => Some(*exchange_id),
            _ => None,
        })
        .collect();
    let http = state.http_case_exchange_indices(case_id, &http_keys)?;
    let mut mysql = BTreeMap::new();
    for (index, exchange) in state.mysql.exchanges.iter().enumerate() {
        let Some(key) = exchange
            .record
            .connection_id
            .zip(exchange.record.query_sequence)
        else {
            continue;
        };
        if exchange.source == ReplaySource::Case
            && exchange.case_id.as_deref() == Some(case_id)
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
    let rpc_pushes = state.redis.pubsub.finite_rpc_pushes(case_id)?;
    let memcached = state.memcached.finite_exchanges(case_id)?;
    let motan = state.motan.finite_exchanges(case_id)?;
    let kafka = state.kafka.finite_exchanges(case_id)?;
    references
        .iter()
        .map(|reference| {
            let exchange = match reference {
                RecordedReference::Redis {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Redis(redis[&(*connection_id, *sequence)]),
                RecordedReference::Mysql {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Mysql(mysql[&(*connection_id, *sequence)]),
                RecordedReference::RedisRpcPush {
                    connection_id,
                    sequence,
                } => DependencyAdapter::RedisRpcPush(
                    *rpc_pushes
                        .get(&(*connection_id, *sequence))
                        .context("finite Redis callback reference is absent from Case inventory")?,
                ),
                RecordedReference::Http { exchange_id } => {
                    DependencyAdapter::Http(http[exchange_id])
                }
                RecordedReference::Connect { event_id } => {
                    return Ok(project(
                        *reference,
                        ExchangeHandle::Connect(
                            state.connect_failures.resolve(case_id, *event_id)?,
                        ),
                    ));
                }
                RecordedReference::Memcached {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Memcached(
                    *memcached
                        .get(&(*connection_id, *sequence))
                        .context("finite Memcached reference absent from Case inventory")?,
                ),
                RecordedReference::Motan {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Motan(
                    *motan
                        .get(&(*connection_id, *sequence))
                        .context("finite Motan reference absent from Case inventory")?,
                ),
                RecordedReference::KafkaProduce {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Kafka(
                    *kafka
                        .get(&("produce", *connection_id, *sequence))
                        .context("finite Kafka reference absent from Case inventory")?,
                ),
                RecordedReference::KafkaFetch {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Kafka(
                    *kafka
                        .get(&("fetch", *connection_id, *sequence))
                        .context("finite Kafka reference absent from Case inventory")?,
                ),
                RecordedReference::KafkaDelivery {
                    connection_id,
                    sequence,
                } => DependencyAdapter::Kafka(
                    *kafka
                        .get(&("delivery", *connection_id, *sequence))
                        .context("finite Kafka reference absent from Case inventory")?,
                ),
            };
            let protocol = exchange.protocol();
            let native = contract(protocol);
            debug_assert_eq!(native.protocol, protocol);
            Ok(project(*reference, ExchangeHandle::Native(exchange)))
        })
        .collect()
}
