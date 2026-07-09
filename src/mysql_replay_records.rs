#[derive(Debug, Default)]
struct ReplayEvents {
    connections: usize,
    connection_events: Vec<ConnectionReport>,
    builtin_queries: Vec<QueryReport>,
    matched_queries: Vec<MatchedQueryReport>,
    unmatched_queries: Vec<QueryReport>,
    unsupported_commands: Vec<QueryReport>,
    metadata_warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ReplayExchange {
    source: ReplaySource,
    case_id: Option<String>,
    identity: MysqlDependencyIdentity,
    record: RecordedMysqlExchange,
    consumed: bool,
}

#[derive(Debug, Clone)]
struct MatchedExchange {
    #[allow(dead_code)]
    source: ReplaySource,
    #[allow(dead_code)]
    index: usize,
    record: RecordedMysqlExchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplaySource {
    Bootstrap,
    Case,
}

#[derive(Debug, Serialize)]
struct ReplayReport {
    version: u8,
    mode: ReplayMode,
    dns_listen: String,
    tcp_listen: String,
    case_dir: String,
    case_dependencies_path: String,
    active_case_id: Option<String>,
    cases: Vec<ReplayCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_dependencies_path: Option<String>,
    targets: Vec<ReplayTarget>,
    connections: usize,
    connection_events: Vec<ConnectionReport>,
    builtin_queries: Vec<QueryReport>,
    matched_queries: Vec<MatchedQueryReport>,
    unmatched_queries: Vec<QueryReport>,
    unsupported_commands: Vec<QueryReport>,
    metadata_warnings: Vec<String>,
    unused_bootstrap_exchanges: Vec<RecordedExchangeSummary>,
    unused_case_exchanges: Vec<RecordedExchangeSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionReport {
    peer_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct QueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Vec<RecordedMysqlValue>>,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recorded_source: Option<ReplaySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recorded_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct MatchedQueryReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    source: ReplaySource,
    index: usize,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Vec<RecordedMysqlValue>>,
    status: String,
}

#[derive(Debug, Clone, Serialize)]
struct RecordedExchangeSummary {
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<TargetKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
    status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
struct TargetKey {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayTarget {
    host: String,
    port: u16,
    fake_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplayMode {
    Single,
    Collection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReplayCaseStatus {
    Pending,
    Active,
    Ended,
}

#[derive(Debug, Clone)]
struct ReplayCase {
    id: String,
    dir: PathBuf,
    dependencies_path: PathBuf,
    status: ReplayCaseStatus,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayCaseReport {
    case_id: String,
    case_dir: String,
    dependencies_path: String,
    status: ReplayCaseStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MysqlDependencyIdentity {
    target: TargetKey,
    database: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Clone)]
struct ReplaySessionIdentity {
    target: Option<TargetKey>,
    database: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
enum DependencyRecord {
    MysqlConnection(Box<RecordedMysqlConnection>),
    MysqlExchange(Box<RecordedMysqlExchange>),
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlConnection {
    id: Uuid,
    target_host: Option<String>,
    target_port: Option<u16>,
    target_addr: Option<String>,
    database: Option<String>,
    username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlExchange {
    connection_id: Option<Uuid>,
    target_host: Option<String>,
    target_port: Option<u16>,
    target_addr: Option<String>,
    database: Option<String>,
    username: Option<String>,
    command: String,
    sql: Option<String>,
    params: Option<Vec<RecordedMysqlValue>>,
    response: RecordedMysqlResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlResponse {
    status: String,
    error_code: Option<u16>,
    error_message: Option<String>,
    affected_rows: Option<u64>,
    last_insert_id: Option<u64>,
    #[serde(default)]
    columns: Vec<RecordedMysqlColumn>,
    #[serde(default)]
    rows: Vec<Vec<RecordedMysqlValue>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedMysqlColumn {
    name: String,
    table: Option<String>,
    column: Option<String>,
    family: String,
    sql_type: String,
    unsigned: Option<bool>,
    bits: Option<u16>,
    nullable: Option<bool>,
    scale: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct RecordedMysqlValue {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<ReplayBodyCapture>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct ReplayBodyCapture {
    encoding: String,
    data: String,
}

#[derive(Debug, Clone)]
struct StatementMetadata {
    param_count: usize,
    columns: Vec<RecordedMysqlColumn>,
}

#[derive(Debug, Clone)]
struct PreparedStatement {
    sql: String,
    param_count: usize,
    last_param_types: Vec<BoundParamType>,
}

#[derive(Debug, Clone)]
struct BoundParamType {
    type_code: u8,
    unsigned: bool,
}

#[derive(Debug, Clone, Copy)]
enum ResultRowEncoding {
    Text,
    Binary,
}

async fn load_dependency_file(
    path: &Path,
    source: ReplaySource,
    case_id: Option<&str>,
    exchanges: &mut Vec<ReplayExchange>,
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
        let DependencyRecord::MysqlConnection(connection) = record else {
            continue;
        };
        if let Some(identity) = identity_from_connection(connection) {
            let target = identity.target.clone();
            targets
                .entry(target.clone())
                .or_insert_with(|| ReplayTarget {
                    host: target.host.clone(),
                    port: target.port,
                    fake_ip: Ipv4Addr::UNSPECIFIED,
                });
            connection_identities.insert(connection.id, identity);
        }
    }

    for record in records {
        let DependencyRecord::MysqlExchange(exchange) = record else {
            continue;
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
        targets
            .entry(identity.target.clone())
            .or_insert_with(|| ReplayTarget {
                host: identity.target.host.clone(),
                port: identity.target.port,
                fake_ip: Ipv4Addr::UNSPECIFIED,
            });
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

async fn discover_replay_cases(
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

    let mut entries = tokio::fs::read_dir(root_dir)
        .await
        .with_context(|| format!("failed to read replay case collection {}", root_dir.display()))?;
    let mut cases = BTreeMap::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .with_context(|| format!("failed to scan replay case collection {}", root_dir.display()))?
    {
        let file_type = entry.file_type().await.with_context(|| {
            format!("failed to inspect replay case entry {}", entry.path().display())
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let case_dir = entry.path();
        let dependencies_path = case_dir.join("dependencies.jsonl");
        if !dependencies_path.is_file() {
            continue;
        }
        let Some(case_id) = path_file_name(&case_dir) else {
            continue;
        };
        cases.insert(
            case_id.clone(),
            ReplayCase {
                id: case_id,
                dir: case_dir,
                dependencies_path,
                status: ReplayCaseStatus::Pending,
            },
        );
    }
    if cases.is_empty() {
        return Err(anyhow!(
            "replay path {} is neither a case directory nor a collection with child dependencies.jsonl files",
            root_dir.display()
        ));
    }
    Ok((ReplayMode::Collection, cases, None))
}

fn path_file_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
}

fn active_case_matches(active_case_id: Option<&str>, exchange: &ReplayExchange) -> bool {
    match exchange.source {
        ReplaySource::Bootstrap => true,
        ReplaySource::Case => exchange.case_id.as_deref() == active_case_id,
    }
}

fn find_upward(start: &Path, filename: &str) -> Option<PathBuf> {
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

fn identity_from_connection(
    connection: &RecordedMysqlConnection,
) -> Option<MysqlDependencyIdentity> {
    let target = target_from_connection(connection)?;
    Some(MysqlDependencyIdentity {
        target,
        database: normalize_optional(&connection.database),
        username: normalize_optional(&connection.username),
    })
}

fn identity_from_exchange(exchange: &RecordedMysqlExchange) -> Option<MysqlDependencyIdentity> {
    let target = target_from_exchange(exchange)?;
    Some(MysqlDependencyIdentity {
        target,
        database: normalize_optional(&exchange.database),
        username: normalize_optional(&exchange.username),
    })
}

fn target_from_connection(connection: &RecordedMysqlConnection) -> Option<TargetKey> {
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

fn target_from_exchange(exchange: &RecordedMysqlExchange) -> Option<TargetKey> {
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

fn target_from_addr(value: &str) -> Option<TargetKey> {
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

fn assign_fake_ips(
    targets: BTreeMap<TargetKey, ReplayTarget>,
    fake_cidr: Ipv4Cidr,
) -> Result<Vec<ReplayTarget>> {
    let mut out = Vec::with_capacity(targets.len());
    for (offset, (_, mut target)) in targets.into_iter().enumerate() {
        let offset = u32::try_from(offset + 1).context("too many replay targets")?;
        target.fake_ip = fake_cidr
            .ip_at(offset)
            .ok_or_else(|| anyhow!("fake CIDR exhausted by replay targets"))?;
        out.push(target);
    }
    Ok(out)
}

fn identity_matches_exchange(
    session: &ReplaySessionIdentity,
    exchange: &MysqlDependencyIdentity,
) -> bool {
    session.target.as_ref() == Some(&exchange.target)
        && normalize_identity_value(session.database.as_deref())
            == normalize_identity_value(exchange.database.as_deref())
        && normalize_identity_value(session.username.as_deref())
            == normalize_identity_value(exchange.username.as_deref())
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_identity_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn normalize_optional(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
