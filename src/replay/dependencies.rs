#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub(super) enum DependencyRecord {
    MysqlConnection(Box<RecordedMysqlConnection>),
    MysqlExchange(Box<RecordedMysqlExchange>),
    HttpExchange(Box<http::RecordedHttpExchange>),
    TcpGatewayConnection(Box<http::RecordedTcpGatewayConnection>),
    RedisConnection(Box<redis::RecordedConnection>),
    RedisExchange(Box<redis::RecordedExchange>),
    RedisPubSubPush(Box<redis::pubsub::RecordedPush>),
    MemcachedConnection(Box<memcached::RecordedConnection>),
    MemcachedExchange(Box<memcached::RecordedExchange>),
    KafkaConnection(Box<kafka::RecordedKafkaConnection>),
    KafkaProduce(Box<kafka::RecordedKafkaProduce>),
    KafkaFetch(Box<kafka::RecordedKafkaFetch>),
    KafkaDelivery(Box<kafka::RecordedKafkaDelivery>),
    MotanConnection(Box<motan::RecordedConnection>),
    MotanExchange(Box<motan::RecordedExchange>),
    ProxyError(Box<RecordedProxyError>),
    #[serde(other)]
    Other,
}

pub(crate) fn validate_index_record(value: &Value) -> Result<()> {
    validate_outcome(value)?;
    let _: DependencyRecord = serde_json::from_value(value.clone())?;
    Ok(())
}

fn validate_outcome(value: &Value) -> Result<()> {
    if let Some(outcome) = value.get("outcome") {
        let outcome = serde_json::from_value::<crate::DependencyExchangeOutcome>(outcome.clone())?;
        outcome.validate()?;
        if outcome.termination().is_some() {
            anyhow::ensure!(
                value
                    .get("duration_ms")
                    .and_then(Value::as_u64)
                    .is_some_and(|duration| duration <= 86_400_000),
                "transport termination requires an explicit bounded request-relative duration_ms"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedProxyError {
    pub(super) protocol: String,
    pub(super) error: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn load_dependency_file(
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
) -> Result<()> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read dependency replay file {}", path.display()))?;
    let records = parse_dependency_records(path, &raw)?;
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
    )
}

pub(super) fn parse_dependency_records(
    path: &Path,
    raw: &str,
) -> Result<Vec<(usize, DependencyRecord)>> {
    let mut records = Vec::new();
    for (line_index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)?;
        validate_outcome(&value).with_context(|| {
            format!(
                "invalid dependency termination at line {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        let record: DependencyRecord = serde_json::from_value(value).with_context(|| {
            format!(
                "failed to parse dependency replay line {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        records.push((line_index + 1, record));
    }

    Ok(records)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn register_dependency_records(
    path: &Path,
    records: Vec<(usize, DependencyRecord)>,
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
) -> Result<()> {
    for (line, record) in &records {
        if skip.contains(line) {
            continue;
        }
        match record {
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
    let transaction_plans =
        mysql::transaction_equivalence::Registry::prepare(&records, &optional_sessions);
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
            | DependencyRecord::Other => continue,
            DependencyRecord::MysqlExchange(_) => {}
        }
        let DependencyRecord::MysqlExchange(exchange) = record else {
            unreachable!("non-MySQL dependency records were handled above")
        };
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
        &mysql.exchanges,
    );
    for (index, kind) in transaction_omissions {
        if mysql.exchanges[index].status.is_available() {
            mysql.exchanges[index].optional_session = Some(kind);
        }
    }
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

pub(super) async fn load_motan_debug_file(
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

pub(super) fn active_case_matches(active_case_id: Option<&str>, exchange: &ReplayExchange) -> bool {
    match exchange.source {
        ReplaySource::Global => true,
        ReplaySource::Case => exchange.case_id.as_deref() == active_case_id,
    }
}

pub(super) fn identity_from_connection(
    connection: &RecordedMysqlConnection,
) -> Option<MysqlDependencyIdentity> {
    let target = target_from_connection(connection)?;
    Some(MysqlDependencyIdentity {
        target,
        database: normalize_optional(&connection.database),
        username: normalize_optional(&connection.username),
    })
}

pub(super) fn identity_from_exchange(
    exchange: &RecordedMysqlExchange,
) -> Option<MysqlDependencyIdentity> {
    let target = target_from_exchange(exchange)?;
    Some(MysqlDependencyIdentity {
        target,
        database: normalize_optional(&exchange.database),
        username: normalize_optional(&exchange.username),
    })
}

pub(super) fn target_from_connection(connection: &RecordedMysqlConnection) -> Option<TargetKey> {
    if let (Some(host), Some(port)) = (&connection.target_host, connection.target_port) {
        return Some(TargetKey {
            host: normalize_host(host),
            port,
        });
    }
    if let Some(target_addr) = &connection.target_addr
        && let Some(target) = target_from_addr(target_addr)
    {
        return Some(target);
    }
    None
}

pub(super) fn target_from_exchange(exchange: &RecordedMysqlExchange) -> Option<TargetKey> {
    if let (Some(host), Some(port)) = (&exchange.target_host, exchange.target_port) {
        return Some(TargetKey {
            host: normalize_host(host),
            port,
        });
    }
    if let Some(target_addr) = &exchange.target_addr
        && let Some(target) = target_from_addr(target_addr)
    {
        return Some(target);
    }
    None
}

pub(super) fn target_from_addr(value: &str) -> Option<TargetKey> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(TargetKey {
            host: normalize_host(&addr.ip().to_string()),
            port: addr.port(),
        });
    }
    let (host, port) = value.rsplit_once(':')?;
    Some(TargetKey {
        host: normalize_host(host.trim_start_matches('[').trim_end_matches(']')),
        port: port.parse().ok()?,
    })
}

pub(super) fn identity_matches_exchange(
    session: &ReplaySessionIdentity,
    exchange: &MysqlDependencyIdentity,
) -> bool {
    session.target.as_ref() == Some(&exchange.target)
        && normalize_identity_value(session.database.as_deref())
            == normalize_identity_value(exchange.database.as_deref())
        && normalize_identity_value(session.username.as_deref())
            == normalize_identity_value(exchange.username.as_deref())
}

pub(super) fn normalize_identity_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

pub(super) fn normalize_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
use super::*;
