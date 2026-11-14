//! Source registration binds native evidence to the shared execution inventory.
use crate::replay::{
    self, RecordedProxyError, ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol,
    ReplayTarget, TargetKey,
};
use crate::replay::{http, kafka, memcached, motan, mysql, native, redis, register_replay_target};
use anyhow::{Context, Result, anyhow, ensure};
use mysql::{MysqlReplayState, ReplayExchange};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use traffic_protocol_mysql::recorded::RecordedMysqlConnection;
use traffic_protocol_mysql::session_identity::DependencyIdentity as MysqlDependencyIdentity;
use uuid::Uuid;
type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
use traffic_protocol_mysql::session_identity::{identity_from_connection, identity_from_exchange};
use traffic_replay::ReplaySource;
mod record;
pub(crate) use record::DependencyRecord;

pub(crate) fn validate_index_record(value: &Value) -> Result<()> {
    replay::dependencies::validate_outcome(value)?;
    let _: DependencyRecord = serde_json::from_value(value.clone())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn load_dependency_file(
    path: &Path,
    source: ReplaySource,
    case_id: Option<&str>,
    mysql: &mut MysqlReplayState,
    http_exchanges: &mut Vec<http::ReplayHttpExchange>,
    http_blackholes: &mut Vec<http::ReplayHttpBlackhole>,
    redis: &mut redis::RedisReplayState,
    memcached: &mut memcached::MemcachedReplayState,
    kafka: &mut kafka::KafkaReplayState,
    motan: &mut motan::MotanReplayState,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    connection_identities: &mut HashMap<Uuid, MysqlDependencyIdentity>,
    process_owned_dependencies: &[crate::BackgroundDependencyRuleConfig],
    native: &mut native::Inventory,
) -> Result<(
    replay::execution_plan::SourceScopeIdentity,
    Vec<replay::report::unused_source::CaptureFact>,
)> {
    let replay::dependencies::SourceRecords {
        records,
        scope,
        facts,
    } = replay::dependencies::read_dependency_file::<DependencyRecord>(path).await?;
    let cleanup = if source == ReplaySource::Case {
        replay::lifecycle_cleanup::load_refs(&crate::dependency_index::scoped::case_directory(
            path,
        )?)
        .await?
    } else {
        BTreeSet::new()
    };
    register_dependency_records(
        path,
        records,
        &BTreeSet::new(),
        source,
        case_id,
        mysql,
        http_exchanges,
        http_blackholes,
        redis,
        memcached,
        kafka,
        motan,
        targets,
        connection_identities,
        process_owned_dependencies,
        &cleanup,
        native,
    )?;
    Ok((scope, facts))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn register_dependency_records(
    path: &Path,
    mut records: Vec<(usize, DependencyRecord)>,
    skip: &BTreeSet<usize>,
    source: ReplaySource,
    case_id: Option<&str>,
    mysql: &mut MysqlReplayState,
    http_exchanges: &mut Vec<http::ReplayHttpExchange>,
    http_blackholes: &mut Vec<http::ReplayHttpBlackhole>,
    redis: &mut redis::RedisReplayState,
    memcached: &mut memcached::MemcachedReplayState,
    kafka: &mut kafka::KafkaReplayState,
    motan: &mut motan::MotanReplayState,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    connection_identities: &mut HashMap<Uuid, MysqlDependencyIdentity>,
    process_owned_dependencies: &[crate::BackgroundDependencyRuleConfig],
    cleanup: &BTreeSet<replay::RecordedReference>,
    native: &mut native::Inventory,
) -> Result<()> {
    ensure!(
        cleanup.is_empty() || source == ReplaySource::Case && case_id.is_some(),
        "lifecycle cleanup has no exact Case owner"
    );
    authorize(&mut records, cleanup)?;
    for (line, record) in &records {
        if skip.contains(line) {
            continue;
        }
        match record {
            DependencyRecord::Native(event) => {
                native.register(event, source, case_id, *line, targets)?;
            }
            DependencyRecord::MysqlConnection(connection) => {
                if let Some(identity) = identity_from_connection(connection) {
                    let target = identity.target.clone();
                    register_replay_target(targets, &target, ReplayProtocol::Mysql)?;
                    connection_identities.insert(connection.id, identity);
                }
            }
            DependencyRecord::RedisPubSubPush(push) => {
                redis.pubsub.register((**push).clone(), source, case_id)?;
            }
            DependencyRecord::RedisConnection(connection) => {
                redis.register_connection((**connection).clone(), targets)?;
            }
            DependencyRecord::MemcachedConnection(connection) => {
                memcached.register_connection((**connection).clone(), targets)?;
            }
            DependencyRecord::KafkaConnection(connection) => {
                kafka.register_connection((**connection).clone(), targets)?;
            }
            DependencyRecord::MotanConnection(connection) => {
                motan.register_connection((**connection).clone(), targets)?;
            }
            DependencyRecord::ProxyError(error) => {
                redis::RedisReplayState::reject_proxy_error(error)?;
                memcached::MemcachedReplayState::reject_proxy_error(error)?;
                motan::MotanReplayState::reject_proxy_error(error)?;
                if error.protocol == "kafka" {
                    return Err(anyhow!(
                        "unsafe Kafka dependency proxy error: {}",
                        error.error
                    ));
                }
            }
            _ => {}
        }
    }

    // Classification always sees the complete original case/connection sequence.
    let (lines, records): (Vec<_>, Vec<_>) = records.into_iter().unzip();
    let optional_sessions =
        mysql::optional_session::classify(&records, source, &mut mysql.read_prefixes);
    let isolation_plans = mysql
        .isolation
        .prepare(mysql::source_records(&records), source, case_id);
    let transaction_plans = mysql.transaction_equivalence.prepare(
        mysql::source_records(&records),
        &optional_sessions,
        source,
    );
    let mut mysql_record_indices = std::collections::BTreeMap::new();
    for (record_index, (line, record)) in lines.into_iter().zip(records).enumerate() {
        if skip.contains(&line) {
            continue;
        }
        match record {
            DependencyRecord::HttpExchange(mut exchange) => {
                exchange.decrypt_request_headers(path)?;
                http::register_http_exchange(*exchange, source, case_id, http_exchanges, targets)?;
                continue;
            }
            DependencyRecord::TcpGatewayConnection(connection) => {
                http::register_tcp_connection_blackhole(
                    *connection,
                    source,
                    case_id,
                    http_blackholes,
                    targets,
                )?;
                continue;
            }
            DependencyRecord::RedisExchange(exchange) => {
                redis.register_exchange(
                    *exchange,
                    source,
                    case_id,
                    targets,
                    process_owned_dependencies,
                )?;
                continue;
            }
            DependencyRecord::MemcachedExchange(exchange) => {
                memcached.register_exchange(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::KafkaProduce(exchange) => {
                kafka.register_produce(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::KafkaFetch(exchange) => {
                kafka.register_fetch(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::KafkaDelivery(exchange) => {
                kafka.register_delivery(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::MotanExchange(exchange) => {
                motan.register_exchange(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::MysqlConnection(_)
            | DependencyRecord::RedisPubSubPush(_)
            | DependencyRecord::RedisConnection(_)
            | DependencyRecord::MemcachedConnection(_)
            | DependencyRecord::KafkaConnection(_)
            | DependencyRecord::MotanConnection(_)
            | DependencyRecord::ProxyError(_)
            | DependencyRecord::ConnectFailure
            | DependencyRecord::Native(_) => continue,
            DependencyRecord::MysqlExchange(_) => {}
        }
        let DependencyRecord::MysqlExchange(exchange) = record else {
            unreachable!("non-MySQL dependency records were handled above")
        };
        ensure!(
            exchange.lifecycle_cleanup
                || !exchange
                    .parse_warnings
                    .iter()
                    .any(|warning| warning == "engine cleanup interrupted MySQL capture"),
            "MySQL engine cleanup record lacks its exact authenticated Source-stop scope"
        );
        if exchange.outcome == crate::DependencyExchangeOutcome::Response
            && (exchange.command == "COM_PING" && exchange.response.status == "ok"
                || exchange.command == "COM_STMT_PREPARE"
                    && exchange.response.status == "stmt_prepare")
        {
            // PING and PREPARE already contributed to session evidence above;
            // they do not create a required business exchange.
            continue;
        }
        if crate::mysql::wire::is_no_response_command(&exchange.command) {
            continue;
        }
        let identity = identity_from_exchange(&exchange)
            .or_else(|| {
                exchange
                    .connection_id
                    .and_then(|connection_id| connection_identities.get(&connection_id).cloned())
            })
            .with_context(|| {
                format!(
                    "mysql_exchange in {} lacks business target/database identity for SQL {:?}",
                    path.display(),
                    exchange.sql
                )
            })?;
        register_replay_target(targets, &identity.target, ReplayProtocol::Mysql)?;
        // Failed PING can still identify a recorded endpoint, but all PINGs
        // are answered by the replay server without a finite Source claim.
        if exchange.command == "COM_PING" || mysql::is_nonsemantic_session_setup(&exchange) {
            continue;
        }
        let timing = ReplayExchangeTiming::from_recorded(exchange.duration_ms, exchange.outcome);
        let mysql_index = mysql.exchanges.len();
        mysql.register_exchange(ReplayExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            identity,
            record: *exchange,
            optional_session: optional_sessions.get(&record_index).copied(),
            status: ReplayExchangeStatus::Available,
            timing,
        });
        if mysql.exchanges.len() > mysql_index {
            mysql_record_indices.insert(record_index, mysql_index);
        }
    }
    let transaction_omissions = mysql.transaction_equivalence.install(
        transaction_plans,
        &mysql_record_indices,
        &mysql::SessionContext(&mysql.exchanges),
    );
    for (index, kind) in transaction_omissions {
        if mysql.exchanges[index].status.is_available() {
            mysql.exchanges[index].optional_session = Some(kind);
        }
    }
    mysql
        .isolation
        .install(isolation_plans, &mysql_record_indices);
    redis.pubsub.validate_links(source, case_id)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
enum DebugDependencyRecord {
    MotanExchange(Box<motan::RecordedExchange>),
    #[serde(other)]
    Other,
}

pub(crate) async fn load_motan_debug_file(
    path: &Path,
    motan: &mut motan::MotanReplayState,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<()> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read dependency debug replay file {}",
                    path.display()
                )
            });
        }
    };
    let mut input = BufReader::new(file).lines();
    let mut line_index = 0;
    while let Some(line) = input.next_line().await? {
        line_index += 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: DebugDependencyRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse dependency debug replay line {} in {}",
                line_index,
                path.display()
            )
        })?;
        if let DebugDependencyRecord::MotanExchange(exchange) = record {
            motan.register_heartbeat(*exchange, targets)?;
        }
    }
    Ok(())
}

pub(crate) fn authorize(
    records: &mut [(usize, DependencyRecord)],
    references: &BTreeSet<replay::RecordedReference>,
) -> Result<()> {
    for (_, record) in records {
        match record {
            DependencyRecord::MysqlExchange(record) => {
                if record.connection_id.zip(record.query_sequence).is_some_and(
                    |(connection_id, sequence)| {
                        references.contains(&replay::RecordedReference::Mysql {
                            connection_id,
                            sequence,
                        })
                    },
                ) {
                    record.authorize_lifecycle_cleanup()?;
                }
            }
            DependencyRecord::RedisExchange(record) => {
                if references.contains(&record.cleanup_reference()) {
                    record.authorize_lifecycle_cleanup()?;
                }
            }
            DependencyRecord::HttpExchange(record)
                if record.exchange_id().is_some_and(|exchange_id| {
                    references.contains(&replay::RecordedReference::Http { exchange_id })
                }) =>
            {
                record.authorize_lifecycle_cleanup()?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Retain small connection/setup and Redis evidence before listeners become ready.
/// Redis overlays and lane classification require a complete selected inventory.
pub(crate) fn startup_records(
    path: &Path,
    index: &crate::dependency_index::FileIndex,
    reader: &mut crate::dependency_index::RecordReader,
) -> Result<Vec<(usize, DependencyRecord)>> {
    let mut records = BTreeMap::new();
    for (line, value) in &index.metadata {
        if value["event_type"] != "indexed_advertised_target" {
            records.insert(*line, serde_json::from_value(value.clone())?);
        }
    }
    for entry in &index.redis {
        let raw = reader.read(path, &index.stamp, &entry.location)?;
        records.insert(entry.location.line, serde_json::from_slice(&raw)?);
    }
    Ok(records.into_iter().collect())
}

pub(crate) struct AppendedSource {
    pub(super) mysql_start: usize,
    pub(super) http_start: usize,
}

pub(crate) mod global;

pub(crate) mod projection;
