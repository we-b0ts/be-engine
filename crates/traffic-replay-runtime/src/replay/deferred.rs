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

pub(crate) async fn prepare_case<P: ReplayProtocolSet>(
    state: Arc<Mutex<RuntimeState<P>>>,
    case_id: &str,
) -> Result<()> {
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
    let (recording, fast_cap, evidence) = {
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
            state.providers.evidence().clone(),
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
        let mut records =
            dependencies::parse_dependency_records::<P::SourceRecord>(&read_path, text)?;
        if let Some(lines) = lines {
            for (line, _) in &mut records {
                *line = *lines
                    .get(*line - 1)
                    .context("selected Source line identity absent")?;
            }
        }
        let input = control::input_timing::PreparedSource::load(
            &recording,
            fast_cap,
            Some(&raw),
            &evidence,
        );
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

fn install<P: ReplayProtocolSet>(
    state: &mut RuntimeState<P>,
    deferred: &DeferredDependencies,
    case_id: &str,
    path: &Path,
    inventory: CaseInventory,
    raw: &[u8],
    records: Vec<(usize, P::SourceRecord)>,
) -> Result<()> {
    // Preserve assigned addresses and validate late targets against the startup inventory.
    let mut targets = deferred.known_targets.clone();
    let appended = state.protocols.register_source(
        dependencies::SourceBatch {
            path,
            records,
            skip: &inventory.skip,
            source: ReplaySource::Case,
            case: Some(case_id),
            process_rules: &deferred.process_rules,
            cleanup: &inventory.cleanup,
        },
        &mut state.native,
        &mut targets,
    )?;
    ensure!(
        targets.len() == deferred.known_targets.len(),
        "case preparation found an endpoint absent from its dependency index"
    );
    state.protocols.index_source(&appended);
    if let Some(policy) = &mut state.replay_policy {
        policy.observe_source(case_id, raw, Some(&inventory.index))?;
        state.protocols.observe_source(&appended, policy);
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
pub(super) fn release_consumed_payloads<P: ReplayProtocolSet>(state: &mut RuntimeState<P>) {
    if state.deferred.is_some() {
        state.protocols.release_payloads(&state.cases);
    }
}
