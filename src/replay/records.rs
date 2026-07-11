#[derive(Debug, Default)]
pub(super) struct ReplayEvents {
    pub(super) connections: usize,
    pub(super) connection_events: Vec<ConnectionReport>,
    pub(super) builtin_queries: Vec<QueryReport>,
    pub(super) matched_queries: Vec<MatchedQueryReport>,
    pub(super) unmatched_queries: Vec<QueryReport>,
    pub(super) unsupported_commands: Vec<QueryReport>,
    pub(super) metadata_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ReplayExchange {
    pub(super) source: ReplaySource,
    pub(super) case_id: Option<String>,
    pub(super) identity: MysqlDependencyIdentity,
    pub(super) record: RecordedMysqlExchange,
    pub(super) consumed: bool,
}

#[derive(Debug, Clone)]
pub(super) struct MatchedExchange {
    #[allow(dead_code)]
    pub(super) source: ReplaySource,
    #[allow(dead_code)]
    pub(super) index: usize,
    pub(super) record: RecordedMysqlExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplaySource {
    Bootstrap,
    Case,
}

#[derive(Debug, Serialize)]
pub(super) struct ReplayReport {
    pub(super) version: u8,
    pub(super) mode: ReplayMode,
    pub(super) dns_listen: String,
    pub(super) tcp_listen: String,
    pub(super) case_dir: String,
    pub(super) case_dependencies_path: String,
    pub(super) active_case_id: Option<String>,
    pub(super) cases: Vec<ReplayCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) bootstrap_dependencies_path: Option<String>,
    pub(super) targets: Vec<ReplayTarget>,
    pub(super) connections: usize,
    pub(super) connection_events: Vec<ConnectionReport>,
    pub(super) builtin_queries: Vec<QueryReport>,
    pub(super) matched_queries: Vec<MatchedQueryReport>,
    pub(super) unmatched_queries: Vec<QueryReport>,
    pub(super) unsupported_commands: Vec<QueryReport>,
    pub(super) metadata_warnings: Vec<String>,
    pub(super) unused_bootstrap_exchanges: Vec<RecordedExchangeSummary>,
    pub(super) unused_case_exchanges: Vec<RecordedExchangeSummary>,
    pub(super) matched_http_exchanges: Vec<http::MatchedHttpExchangeReport>,
    pub(super) unmatched_http_requests: Vec<http::HttpRequestReport>,
    pub(super) unsupported_http_exchanges: Vec<http::HttpRequestReport>,
    pub(super) unused_bootstrap_http_exchanges: Vec<http::RecordedHttpExchangeSummary>,
    pub(super) unused_case_http_exchanges: Vec<http::RecordedHttpExchangeSummary>,
    #[serde(flatten)]
    pub(super) protocols: cache::CacheProtocolsReport,
    pub(super) ca_cert_path: String,
    pub(super) http_ignored_query_params: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ConnectionReport {
    pub(super) peer_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct QueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
    pub(super) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) params: Option<Vec<RecordedMysqlValue>>,
    pub(super) reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recorded_source: Option<ReplaySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recorded_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MatchedQueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
    pub(super) source: ReplaySource,
    pub(super) index: usize,
    pub(super) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) params: Option<Vec<RecordedMysqlValue>>,
    pub(super) status: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct RecordedExchangeSummary {
    pub(super) index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) username: Option<String>,
    pub(super) command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) sql: Option<String>,
    pub(super) status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub(super) struct TargetKey {
    pub(super) host: String,
    pub(super) port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ReplayTarget {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) fake_ip: Ipv4Addr,
    pub(super) protocol: ReplayProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayProtocol {
    Mysql,
    Http,
    Https,
    Redis,
    Memcached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayMode {
    Single,
    Collection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayCaseStatus {
    Pending,
    Active,
    Ended,
}

#[derive(Debug, Clone)]
pub(super) struct ReplayCase {
    pub(super) id: String,
    pub(super) dir: PathBuf,
    pub(super) dependencies_path: PathBuf,
    pub(super) status: ReplayCaseStatus,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ReplayCaseReport {
    pub(super) case_id: String,
    pub(super) case_dir: String,
    pub(super) dependencies_path: String,
    pub(super) status: ReplayCaseStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MysqlDependencyIdentity {
    pub(super) target: TargetKey,
    pub(super) database: Option<String>,
    pub(super) username: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ReplaySessionIdentity {
    pub(super) target: Option<TargetKey>,
    pub(super) database: Option<String>,
    pub(super) username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub(super) enum DependencyRecord {
    MysqlConnection(Box<RecordedMysqlConnection>),
    MysqlExchange(Box<RecordedMysqlExchange>),
    HttpExchange(Box<http::RecordedHttpExchange>),
    RedisConnection(Box<cache::RecordedRedisConnection>),
    RedisExchange(Box<cache::RecordedRedisExchange>),
    MemcachedConnection(Box<cache::RecordedMemcachedConnection>),
    MemcachedExchange(Box<cache::RecordedMemcachedExchange>),
    ProxyError(Box<cache::RecordedCacheProxyError>),
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedMysqlConnection {
    pub(super) id: Uuid,
    pub(super) target_host: Option<String>,
    pub(super) target_port: Option<u16>,
    pub(super) target_addr: Option<String>,
    pub(super) database: Option<String>,
    pub(super) username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedMysqlExchange {
    pub(super) connection_id: Option<Uuid>,
    pub(super) target_host: Option<String>,
    pub(super) target_port: Option<u16>,
    pub(super) target_addr: Option<String>,
    pub(super) database: Option<String>,
    pub(super) username: Option<String>,
    pub(super) command: String,
    pub(super) sql: Option<String>,
    pub(super) params: Option<Vec<RecordedMysqlValue>>,
    pub(super) response: RecordedMysqlResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedMysqlResponse {
    pub(super) status: String,
    pub(super) error_code: Option<u16>,
    pub(super) error_message: Option<String>,
    pub(super) affected_rows: Option<u64>,
    pub(super) last_insert_id: Option<u64>,
    #[serde(default)]
    pub(super) columns: Vec<RecordedMysqlColumn>,
    #[serde(default)]
    pub(super) rows: Vec<Vec<RecordedMysqlValue>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RecordedMysqlColumn {
    pub(super) name: String,
    pub(super) table: Option<String>,
    pub(super) column: Option<String>,
    pub(super) family: String,
    pub(super) sql_type: String,
    pub(super) unsigned: Option<bool>,
    pub(super) bits: Option<u16>,
    pub(super) nullable: Option<bool>,
    pub(super) scale: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(super) struct RecordedMysqlValue {
    pub(super) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) raw: Option<ReplayBodyCapture>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub(super) struct ReplayBodyCapture {
    pub(super) encoding: String,
    pub(super) data: String,
}

#[derive(Debug, Clone)]
pub(super) struct StatementMetadata {
    pub(super) param_count: usize,
    pub(super) columns: Vec<RecordedMysqlColumn>,
}

#[derive(Debug, Clone)]
pub(super) struct PreparedStatement {
    pub(super) sql: String,
    pub(super) param_count: usize,
    pub(super) last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
pub(super) struct BoundParamType {
    pub(super) type_code: u8,
    pub(super) unsigned: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ResultRowEncoding {
    Text,
    Binary,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn load_dependency_file(
    path: &Path,
    source: ReplaySource,
    case_id: Option<&str>,
    exchanges: &mut Vec<ReplayExchange>,
    http_exchanges: &mut Vec<http::ReplayHttpExchange>,
    cache: &mut cache::CacheReplayState,
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
                cache.register_redis_connection((**connection).clone(), targets)?;
            }
            DependencyRecord::MemcachedConnection(connection) => {
                cache.register_memcached_connection((**connection).clone(), targets)?;
            }
            DependencyRecord::ProxyError(error) => {
                cache::CacheReplayState::reject_cache_proxy_error(error)?;
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
                cache.register_redis_exchange(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::MemcachedExchange(exchange) => {
                cache.register_memcached_exchange(*exchange, source, case_id, targets)?;
                continue;
            }
            DependencyRecord::MysqlConnection(_)
            | DependencyRecord::RedisConnection(_)
            | DependencyRecord::MemcachedConnection(_)
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

pub(super) fn register_replay_target(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    target: &TargetKey,
    protocol: ReplayProtocol,
) -> Result<()> {
    if let Some(existing) = targets.get(target) {
        if existing.protocol != protocol {
            return Err(anyhow!(
                "replay target {}:{} is recorded as both {:?} and {:?}",
                target.host,
                target.port,
                existing.protocol,
                protocol
            ));
        }
        return Ok(());
    }
    targets.insert(
        target.clone(),
        ReplayTarget {
            host: target.host.clone(),
            port: target.port,
            fake_ip: Ipv4Addr::UNSPECIFIED,
            protocol,
        },
    );
    Ok(())
}

pub(super) async fn discover_replay_cases(
    root_dir: &Path,
) -> Result<(ReplayMode, BTreeMap<String, ReplayCase>, Option<String>)> {
    let direct_dependencies = root_dir.join("dependencies.jsonl");
    if direct_dependencies.is_file() {
        let case_id = path_file_name(root_dir).unwrap_or_else(|| "case".to_string());
        let mut cases = BTreeMap::new();
        cases.insert(
            case_id.clone(),
            ReplayCase {
                id: case_id.clone(),
                dir: root_dir.to_path_buf(),
                dependencies_path: direct_dependencies,
                status: ReplayCaseStatus::Pending,
            },
        );
        return Ok((ReplayMode::Single, cases, Some(case_id)));
    }

    let mut cases = BTreeMap::new();
    let mut pending = vec![root_dir.to_path_buf()];
    while let Some(scan_dir) = pending.pop() {
        let dependencies_path = scan_dir.join("dependencies.jsonl");
        if !dependencies_path.is_file() {
            let mut entries = tokio::fs::read_dir(&scan_dir).await.with_context(|| {
                format!(
                    "failed to read replay case collection {}",
                    scan_dir.display()
                )
            })?;
            while let Some(entry) = entries.next_entry().await.with_context(|| {
                format!(
                    "failed to scan replay case collection {}",
                    scan_dir.display()
                )
            })? {
                let file_type = entry.file_type().await.with_context(|| {
                    format!(
                        "failed to inspect replay case entry {}",
                        entry.path().display()
                    )
                })?;
                if !file_type.is_dir() {
                    continue;
                }
                let child = entry.path();
                if should_skip_replay_scan_dir(&child) {
                    continue;
                }
                pending.push(child);
            }
            continue;
        }

        let Some(case_id) = path_file_name(&scan_dir) else {
            continue;
        };
        if cases.contains_key(&case_id) {
            return Err(anyhow!(
                "duplicate replay case id {case_id:?} under {}; pass a narrower case collection or re-record with unique case ids",
                root_dir.display()
            ));
        }
        cases.insert(
            case_id.clone(),
            ReplayCase {
                id: case_id,
                dir: scan_dir,
                dependencies_path,
                status: ReplayCaseStatus::Pending,
            },
        );
    }
    if cases.is_empty() {
        return Err(anyhow!(
            "replay path {} is neither a case directory nor a collection/run directory with dependencies.jsonl case files",
            root_dir.display()
        ));
    }
    Ok((ReplayMode::Collection, cases, None))
}

pub(super) fn should_skip_replay_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "failed" | "staging" | ".replay"))
}

pub(super) fn path_file_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
}

pub(super) fn active_case_matches(active_case_id: Option<&str>, exchange: &ReplayExchange) -> bool {
    match exchange.source {
        ReplaySource::Bootstrap => true,
        ReplaySource::Case => exchange.case_id.as_deref() == active_case_id,
    }
}

pub(super) fn find_upward(start: &Path, filename: &str) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
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

pub(super) fn assign_fake_ips(
    targets: BTreeMap<TargetKey, ReplayTarget>,
    fake_cidr: Ipv4Cidr,
) -> Result<Vec<ReplayTarget>> {
    let mut out = Vec::with_capacity(targets.len());
    let mut host_ips = BTreeMap::new();
    for (_, mut target) in targets {
        let fake_ip = if let Some(fake_ip) = host_ips.get(&target.host) {
            *fake_ip
        } else {
            let offset = u32::try_from(host_ips.len() + 1).context("too many replay hosts")?;
            let fake_ip = fake_cidr
                .ip_at(offset)
                .ok_or_else(|| anyhow!("fake CIDR exhausted by replay hosts"))?;
            host_ips.insert(target.host.clone(), fake_ip);
            fake_ip
        };
        target.fake_ip = fake_ip;
        out.push(target);
    }
    Ok(out)
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

pub(super) fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
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
