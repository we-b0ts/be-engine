//! Case preparation owns immutable reads; ReplayState retains finite consumption.
use super::*;
pub(super) mod prefetch;
#[cfg(test)]
mod recorded_skip_tests;
mod scoped_read;
#[cfg(test)]
mod tests;
use crate::dependency_index::{FileIndex, RecordLocation, RecordReader};

#[derive(Debug, Clone)]
pub(super) struct CaseInventory {
    pub index: Arc<FileIndex>,
    pub source_bytes: u64,
    pub skip: BTreeSet<usize>,
    pub cleanup: BTreeSet<control::dependency_tail::RecordedReference>,
}

#[derive(Debug)]
pub(super) struct DeferredDependencies {
    pub files: BTreeMap<String, CaseInventory>,
    pub reader: Arc<std::sync::Mutex<RecordReader>>,
    pub identities: HashMap<Uuid, MysqlDependencyIdentity>,
    pub process_rules: Vec<crate::BackgroundDependencyRuleConfig>,
    pub known_targets: BTreeMap<TargetKey, ReplayTarget>,
    pub timeout: std::time::Duration,
    pub cache_bytes: usize,
    pub prefetch_tx: tokio::sync::mpsc::Sender<(PathBuf, Arc<FileIndex>)>,
    pub prefetch_rx: Mutex<tokio::sync::mpsc::Receiver<(PathBuf, Arc<FileIndex>)>>,
    serial: Mutex<()>,
    loaded: std::sync::Mutex<BTreeSet<String>>,
    failed: std::sync::Mutex<BTreeMap<String, String>>,
}

impl DeferredDependencies {
    pub fn new(
        files: BTreeMap<String, CaseInventory>,
        reader: Arc<std::sync::Mutex<RecordReader>>,
        identities: HashMap<Uuid, MysqlDependencyIdentity>,
        process_rules: Vec<crate::BackgroundDependencyRuleConfig>,
        seconds: u64,
        cache_bytes: usize,
        known_targets: BTreeMap<TargetKey, ReplayTarget>,
    ) -> Self {
        let (prefetch_tx, prefetch_rx) = tokio::sync::mpsc::channel(1);
        Self {
            cache_bytes,
            known_targets,
            prefetch_tx,
            prefetch_rx: Mutex::new(prefetch_rx),
            files,
            reader,
            identities,
            process_rules,
            timeout: std::time::Duration::from_secs(seconds),
            serial: Mutex::new(()),
            loaded: Default::default(),
            failed: Default::default(),
        }
    }
}

pub(super) fn register_index_targets(
    index: &FileIndex,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    providers: &crate::protocols::DependencyProviders,
) -> Result<()> {
    for endpoint in &index.endpoints {
        register_replay_target(
            targets,
            &TargetKey {
                host: endpoint.host.clone(),
                port: endpoint.port,
            },
            ReplayProtocol::resolve(&endpoint.protocol, providers)?,
        )?;
    }
    for (_, value) in &index.metadata {
        if value["event_type"] == "indexed_advertised_target" {
            let value = &value["target"];
            register_replay_target_at(
                targets,
                &TargetKey {
                    host: normalize_host(
                        value["alias"]
                            .as_str()
                            .context("advertised alias missing")?,
                    ),
                    port: u16::try_from(
                        value["port"].as_u64().context("advertised port missing")?,
                    )?,
                },
                ReplayProtocol::resolve(
                    value["protocol"]
                        .as_str()
                        .context("advertised protocol missing")?,
                    providers,
                )?,
                Some(
                    value["advertised_ip"]
                        .as_str()
                        .context("advertised IP missing")?
                        .parse()?,
                ),
            )?;
        }
    }
    Ok(())
}

/// Retain small connection/setup and Redis evidence before listeners become ready.
/// Redis overlays and lane classification require a complete selected inventory.
pub(super) fn startup_records(
    path: &Path,
    index: &FileIndex,
    reader: &mut RecordReader,
) -> Result<Vec<(usize, dependencies::DependencyRecord)>> {
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

pub(super) async fn prepare_case(state: Arc<Mutex<ReplayState>>, case_id: &str) -> Result<()> {
    let deferred = state.lock().await.deferred.clone();
    let Some(deferred) = deferred else {
        return Ok(());
    };
    let _serial = deferred.serial.lock().await;
    if deferred
        .loaded
        .lock()
        .expect("loaded case set")
        .contains(case_id)
    {
        return Ok(());
    }
    if let Some(error) = deferred
        .failed
        .lock()
        .expect("failed case set")
        .get(case_id)
    {
        anyhow::bail!("case dependency preparation previously failed: {error}");
    }
    let (recording, fast_cap) = {
        let state = state.lock().await;
        ensure!(
            state.finalized_at.is_none(),
            "Replay session already finalized"
        );
        ensure!(
            state
                .active_case_id
                .as_deref()
                .is_none_or(|id| id == case_id),
            "another replay case is active"
        );
        let recording = state.cases.get(case_id).context("unknown replay case")?;
        (
            recording.clone(),
            control::input_timing::source_fast_cap(&state),
        )
    };
    let path = recording.dependencies_path.clone();
    let inventory = deferred
        .files
        .get(case_id)
        .context("case dependency index missing")?
        .clone();
    let reader = deferred.reader.clone();
    let read_path = path.clone();
    let started = std::time::Instant::now();
    info!(
        case_id,
        source_bytes = inventory.source_bytes,
        "preparing replay case dependencies"
    );
    let task = tokio::task::spawn_blocking(move || -> Result<_> {
        let (raw, lines) = scoped_read::read(&read_path, &inventory.index, &reader)?;
        let text = std::str::from_utf8(&raw)?;
        let mut records = dependencies::parse_dependency_records(&read_path, text)?;
        if let Some(lines) = lines {
            for (line, _) in &mut records {
                *line = *lines
                    .get(*line - 1)
                    .context("selected Source line identity absent")?;
            }
        }
        let input = control::input_timing::PreparedSource::load(&recording, fast_cap, Some(&raw));
        Ok((inventory, raw, records, input))
    });
    let prepared = match tokio::time::timeout(deferred.timeout, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(anyhow!(
            "case dependency preparation exceeded {}s",
            deferred.timeout.as_secs()
        )),
    };
    let (inventory, raw, records, input) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            deferred
                .failed
                .lock()
                .expect("failed case set")
                .insert(case_id.into(), format!("{error:#}"));
            return Err(error);
        }
    };
    let mut state = state.lock().await;
    ensure!(
        state.finalized_at.is_none(),
        "Replay session already finalized"
    );
    ensure!(
        state
            .active_case_id
            .as_deref()
            .is_none_or(|id| id == case_id),
        "another replay case became active"
    );
    let result = install(
        &mut state, &deferred, case_id, &path, inventory, &raw, records,
    );
    if let Err(error) = &result {
        // A failed installation cannot be retried and duplicate finite exchanges.
        deferred
            .failed
            .lock()
            .expect("failed case set")
            .insert(case_id.into(), format!("{error:#}"));
    } else {
        state.prepared_socketio_input = Some(input);
        deferred
            .loaded
            .lock()
            .expect("loaded case set")
            .insert(case_id.into());
        info!(
            case_id,
            elapsed_ms = started.elapsed().as_millis(),
            "replay case dependencies ready"
        );
    }
    result
}

fn install(
    state: &mut ReplayState,
    deferred: &DeferredDependencies,
    case_id: &str,
    path: &Path,
    inventory: CaseInventory,
    raw: &[u8],
    records: Vec<(usize, dependencies::DependencyRecord)>,
) -> Result<()> {
    let mysql_start = state.protocols.mysql.exchanges.len();
    let http_start = state.protocols.http_exchanges.len();
    // Preserve assigned addresses and validate every late target against startup inventory.
    let mut targets = deferred.known_targets.clone();
    let mut identities = deferred.identities.clone();
    dependencies::register_dependency_records(
        path,
        records,
        &inventory.skip,
        ReplaySource::Case,
        Some(case_id),
        &mut state.protocols.mysql,
        &mut state.protocols.http_exchanges,
        &mut state.protocols.http_blackholes,
        &mut state.protocols.redis,
        &mut state.protocols.memcached,
        &mut state.protocols.kafka,
        &mut state.protocols.motan,
        &mut targets,
        &mut identities,
        &deferred.process_rules,
        &inventory.cleanup,
        &mut state.native,
    )?;
    ensure!(
        targets.len() == deferred.known_targets.len(),
        "case preparation found an endpoint absent from its dependency index"
    );
    http::extend_case_exchange_index(
        &mut state.protocols.http_case_exchange_index,
        &state.protocols.http_exchanges,
        http_start,
    );
    state
        .protocols
        .http_ingress
        .register(&state.protocols.http_exchanges[http_start..]);
    if let Some(policy) = &mut state.replay_policy {
        policy
            .request_contracts
            .observe_source(case_id, raw, Some(&inventory.index))?;
        if policy.dynamic_values.enabled() {
            policy.dynamic_values.observe_source(case_id, raw)?;
        }
        for (offset, exchange) in state.protocols.mysql.exchanges[mysql_start..]
            .iter()
            .enumerate()
        {
            policy.observe_recorded_mysql_exchange(
                exchange.case_id.as_deref(),
                &ReplaySessionIdentity {
                    target: Some(exchange.identity.target.clone()),
                    database: exchange.identity.database.clone(),
                    username: exchange.identity.username.clone(),
                },
                &exchange.record.command,
                exchange.record.sql.as_deref(),
                Some(mysql_start + offset),
            );
        }
        http::observe_recorded_policy_exchanges(
            policy,
            &state.protocols.http_exchanges[http_start..],
        );
        memcached::observe_recorded_policy_exchanges(policy, &state.protocols.memcached);
    }
    state.prepare_native_candidates();
    state.install_case_execution_plan(
        case_id,
        execution_plan::SourceScopeIdentity {
            sha256: inventory.index.sha256.clone(),
            source_bytes: inventory.source_bytes,
        },
    )?;
    Ok(())
}

/// Keep vector positions, metadata, counters and unavailable statuses stable.
/// Responses currently owned by a driver are retained until a later sweep.
pub(super) fn release_consumed_payloads(state: &mut ReplayState) {
    if state.deferred.is_none() {
        return;
    }
    for exchange in &mut state.protocols.mysql.exchanges {
        if exchange.source == ReplaySource::Case
            && exchange.status.is_consumed()
            && exchange.case_id.as_ref().is_some_and(|id| {
                state
                    .cases
                    .get(id)
                    .is_some_and(|case| case.status == ReplayCaseStatus::Ended)
            })
        {
            exchange.record.response.rows = Vec::new();
        }
    }
    http::release_consumed_payloads(&mut state.protocols.http_exchanges, &state.cases);
    state
        .protocols
        .memcached
        .release_consumed_payloads(&state.cases);
    state
        .protocols
        .motan
        .release_consumed_payloads(&state.cases);
    state
        .protocols
        .kafka
        .release_consumed_payloads(&state.cases);
}
