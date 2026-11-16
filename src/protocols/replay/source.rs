//! Source registration binds native evidence to the shared execution inventory.
use crate::protocols::replay::http;
use crate::protocols::replay::mysql;
use crate::replay::{
    self, RecordedProxyError, ReplayExchangeStatus, ReplayExchangeTiming, ReplayProtocol,
    ReplayTarget, TargetKey,
};
use crate::{replay::native, replay::register_replay_target};
use anyhow::{Context, Result, ensure};
use mysql::{MysqlReplayState, ReplayExchange};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};
use traffic_protocol_mysql::recorded::RecordedMysqlConnection;
use traffic_protocol_mysql::session_identity::DependencyIdentity as MysqlDependencyIdentity;
use uuid::Uuid;
type RecordedMysqlExchange =
    traffic_protocol_mysql::recorded::RecordedMysqlExchange<crate::dependency_index::RecordRef>;
use traffic_protocol_mysql::session_identity::{identity_from_connection, identity_from_exchange};
use traffic_replay::ReplaySource;
pub(crate) mod preparation;
mod record;
pub(crate) use record::DependencyRecord;

fn validate_installed_provider(
    event: &Value,
    providers: &crate::protocols::DependencyProviders,
) -> Result<()> {
    let kind = event["event_type"].as_str().unwrap_or_default();
    if ["memcached_", "motan_", "kafka_"]
        .iter()
        .any(|prefix| kind.starts_with(prefix))
    {
        ensure!(
            providers.event_provider(event).is_some(),
            "recording event {kind:?} has no installed protocol implementation"
        );
    }
    Ok(())
}

fn reject_retired_proxy_error(error: &RecordedProxyError) -> Result<()> {
    ensure!(
        !matches!(error.protocol.as_str(), "memcached" | "motan" | "kafka"),
        "unsafe dependency proxy error for protocol {}: {}",
        error.protocol,
        error.error
    );
    Ok(())
}

pub(crate) fn validate_index_record(value: &Value) -> Result<()> {
    replay::dependencies::validate_outcome(value)?;
    let _: DependencyRecord = serde_json::from_value(value.clone())?;
    Ok(())
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
                validate_installed_provider(event, &native.providers)?;
                native.register(event, source, case_id, *line, targets)?;
            }
            DependencyRecord::MysqlConnection(connection) => {
                if let Some(identity) = identity_from_connection(connection) {
                    let target = identity.target.clone();
                    register_replay_target(targets, &target, ReplayProtocol::Mysql)?;
                    connection_identities.insert(connection.id, identity);
                }
            }
            DependencyRecord::ProxyError(error) => {
                ensure!(
                    error.protocol != "redis",
                    "unsafe Redis capture proxy error"
                );

                reject_retired_proxy_error(error)?;
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
            DependencyRecord::MysqlConnection(_)
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
                        references.contains(&replay::RecordedReference::connection(
                            "mysql",
                            connection_id,
                            sequence,
                        ))
                    },
                ) {
                    record.authorize_lifecycle_cleanup()?;
                }
            }
            DependencyRecord::HttpExchange(record)
                if record.exchange_id().is_some_and(|exchange_id| {
                    references.contains(&replay::RecordedReference::exchange("http", exchange_id))
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

#[cfg(test)]
mod tests;
