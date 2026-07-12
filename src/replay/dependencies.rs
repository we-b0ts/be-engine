#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub(super) enum DependencyRecord {
    MysqlConnection(Box<RecordedMysqlConnection>),
    MysqlExchange(Box<RecordedMysqlExchange>),
    HttpExchange(Box<http::RecordedHttpExchange>),
    RedisConnection(Box<redis::RecordedConnection>),
    RedisExchange(Box<redis::RecordedExchange>),
    MemcachedConnection(Box<memcached::RecordedConnection>),
    MemcachedExchange(Box<memcached::RecordedExchange>),
    KafkaConnection(Box<kafka::RecordedKafkaConnection>),
    KafkaProduce(Box<kafka::RecordedKafkaProduce>),
    KafkaDelivery(Box<kafka::RecordedKafkaDelivery>),
    ProxyError(Box<RecordedProxyError>),
    #[serde(other)]
    Other,
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
    exchanges: &mut Vec<ReplayExchange>,
    http_exchanges: &mut Vec<http::ReplayHttpExchange>,
    redis: &mut redis::RedisReplayState,
    memcached: &mut memcached::MemcachedReplayState,
    kafka: &mut kafka::KafkaReplayState,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    connection_identities: &mut HashMap<Uuid, MysqlDependencyIdentity>,
) -> Result<()> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read dependency replay file {}", path.display()))?;
    let mut records = Vec::new();
    for (line_index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: DependencyRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse dependency replay line {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }

    for record in &records {
        match record {
            DependencyRecord::MysqlConnection(connection) => {
                if let Some(identity) = identity_from_connection(connection) {
                    let target = identity.target.clone();
                    register_replay_target(targets, &target, ReplayProtocol::Mysql)?;
                    connection_identities.insert(connection.id, identity);
                }
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
            DependencyRecord::ProxyError(error) => {
                redis::RedisReplayState::reject_proxy_error(error)?;
                memcached::MemcachedReplayState::reject_proxy_error(error)?;
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

    for record in records {
        match record {
            DependencyRecord::HttpExchange(exchange) => {
                http::register_http_exchange(*exchange, source, case_id, http_exchanges, targets)?;
                continue;
            }
            DependencyRecord::RedisExchange(exchange) => {
                redis.register_exchange(*exchange, source, case_id, targets)?;
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
            DependencyRecord::KafkaDelivery(exchange) => {
                kafka.register_delivery(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::MysqlConnection(_)
            | DependencyRecord::RedisConnection(_)
            | DependencyRecord::MemcachedConnection(_)
            | DependencyRecord::KafkaConnection(_)
            | DependencyRecord::ProxyError(_)
            | DependencyRecord::Other => continue,
            DependencyRecord::MysqlExchange(_) => {}
        }
        let DependencyRecord::MysqlExchange(exchange) = record else {
            unreachable!("non-MySQL dependency records were handled above")
        };
        if exchange.command == "COM_STMT_PREPARE" && exchange.response.status == "stmt_prepare" {
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
        exchanges.push(ReplayExchange {
            source,
            case_id: case_id.map(ToOwned::to_owned),
            identity,
            record: *exchange,
            consumed: false,
        });
    }
    Ok(())
}

pub(super) fn active_case_matches(active_case_id: Option<&str>, exchange: &ReplayExchange) -> bool {
    match exchange.source {
        ReplaySource::Bootstrap => true,
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
