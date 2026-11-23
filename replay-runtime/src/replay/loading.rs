//! Replay startup inventory construction.
use super::*;
use protocol_runtime::loading::{ProtocolSourceLoader, SourcePreparation, SourceResources};

impl<P: ReplayProtocolSet> Runtime<P> {
    pub(crate) async fn from_source(
        config: RuntimeConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
        lifecycle: ReplayLifecycleConfig,
        providers: Arc<crate::protocols::DependencyProviders>,
        loader: P::SourceLoader,
        timers: timers::Timers,
    ) -> Result<Self> {
        // Keep the injected loader and Source preparation state on the heap across startup.
        let loaded = Box::pin(load_state(
            config, dns_listen, tcp_listen, lifecycle, providers, loader, timers,
        ))
        .await?;
        let runtime = Self {
            state: loaded.state,
            ca: loaded.ca,
            report_path: loaded.report_path,
            session_path: loaded.session_path,
            control_socket_path: loaded.control_socket_path,
        };
        // A single-directory Replay starts with an implicit active case.
        let initial_case = runtime.state.lock().await.active_case_id.clone();
        if let Some(case_id) = initial_case {
            deferred::prepare_case(runtime.state.clone(), &case_id).await?;
            control::dependency_tail::prepare(&runtime.state, &case_id).await?;
            control::input_timing::prepare_source(&runtime.state, &case_id).await?;
            let mut state = runtime.state.lock().await;
            control::dependency_tail::activate(&mut state, &case_id)?;
            state.activate_sequence(Some(&case_id));
        }
        Ok(runtime)
    }
}

struct LoadedRuntime<P: ReplayProtocolSet> {
    state: Arc<Mutex<RuntimeState<P>>>,
    ca: Arc<MitmCa>,
    report_path: Option<PathBuf>,
    session_path: Option<PathBuf>,
    control_socket_path: Option<PathBuf>,
}

async fn load_state<P: ReplayProtocolSet>(
    config: RuntimeConfig,
    dns_listen: SocketAddr,
    tcp_listen: SocketAddr,
    lifecycle: ReplayLifecycleConfig,
    providers: Arc<crate::protocols::DependencyProviders>,
    mut loader: P::SourceLoader,
    timers: timers::Timers,
) -> Result<LoadedRuntime<P>> {
    lifecycle.dependency_loading.validate()?;
    ensure!(
        !lifecycle.case_no_progress_timeout.is_zero(),
        "Replay case no-progress timeout must be positive"
    );
    let lazy = lifecycle.dependency_loading.lazy_cases;
    clear_report_artifacts(config.report_path.as_deref()).await?;
    let root_dir = config.case_dir;
    let source_inventory_id =
        if let Some(source) = crate::dependency_index::recording::root(&root_dir) {
            Some(
                tokio::task::spawn_blocking(move || -> Result<String> {
                    let path = source.join(crate::dependency::observation::MANIFEST_FILE);
                    let bytes = std::fs::read(&path)?;
                    Ok(crate::policy_evidence::digest(&bytes))
                })
                .await
                .context("recording authentication task failed")??,
            )
        } else {
            None
        };
    let process_owned_dependencies = &config.process_owned_dependencies;
    let event_source = root_dir.clone();
    let sequence_catalog = tokio::task::spawn_blocking(move || sequence::load(&event_source))
        .await
        .context("Source event preparation task failed")??;
    let replay_artifact_dir = config
        .report_path
        .as_ref()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root_dir.join(".replay"));
    let ca_cert_path = config
        .ca_cert_path
        .unwrap_or_else(|| replay_artifact_dir.join("replay-ca.pem"));
    let ca_key_path = config
        .ca_key_path
        .unwrap_or_else(|| replay_artifact_dir.join("replay-ca-key.pem"));
    let selected_case_ids = config
        .selected_case_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    let (mode, mut cases, active_case_id) =
        discover_replay_cases(&root_dir, &selected_case_ids).await?;
    let source = root_dir.clone();
    let output = replay_artifact_dir.clone();
    let evidence = providers.evidence().clone();
    let (prepared_cases, attribution) = tokio::task::spawn_blocking(move || -> Result<_> {
        let frozen = attribution::freeze(&source, &output, &mut cases, &evidence)?;
        Ok((cases, frozen))
    })
    .await
    .context("dependency attribution snapshot preparation failed")??;
    let mut cases = prepared_cases;
    if let Some(case_id) = &active_case_id
        && let Some(case) = cases.get_mut(case_id)
    {
        case.status = ReplayCaseStatus::Active;
    }
    let policy_path = config.policy_path;
    let (mut replay_policy, cases) = tokio::task::spawn_blocking(move || -> Result<_> {
        let policy = policy_path
            .as_deref()
            .map(|path| P::Policy::load(path, &cases, !lazy))
            .transpose()?;
        Ok((policy, cases))
    })
    .await
    .context("Replay policy preparation task failed")??;
    let ca = Arc::new(MitmCa::load_or_generate(&ca_cert_path, &ca_key_path)?);
    let (_, global_debug_path) = find_run_level_dependencies(&root_dir);
    let global_path = attribution.startup;
    loader.install_run_scopes(attribution.run_value_scopes);
    let mut connect_failures = connect_failure::Inventory::default();
    let mut native = native::Inventory::new(providers.clone());
    let native_policy = replay_policy
        .as_ref()
        .map(|policy| policy.contracts().native_rules());
    native.configure_storage_preparation(native_policy.as_deref());
    let mut resources = SourceResources {
        native,
        targets: BTreeMap::new(),
        reader: Arc::new(std::sync::Mutex::new(
            crate::dependency_index::RecordReader::for_replay(
                lifecycle.dependency_loading.cache_bytes,
            ),
        )),
    };
    let fake_cidr = Ipv4Cidr::parse(&config.fake_cidr)?;
    let total_cases = cases.len();
    let mut next_progress_percent = 5;
    info!(
        loaded_cases = 0,
        total_cases,
        progress_percent = 0,
        case_source = %root_dir.display(),
        "loading replay case dependencies"
    );

    for (path, scope) in [
        (global_path.as_deref(), ReplaySource::Startup),
        (attribution.process.as_deref(), ReplaySource::Process),
        (
            attribution.unattributed.as_deref(),
            ReplaySource::Unattributed,
        ),
    ] {
        if let Some(path) = path {
            loader
                .load_run(path, scope, process_owned_dependencies, &mut resources)
                .await?;
        }
    }
    // Source-owned positions are frozen before selected Case inventories.
    loader.freeze_global_layout();
    resources.native.freeze_global_report_layout();
    loader
        .prepare_run(&root_dir, global_debug_path, &mut resources)
        .await?;
    let case_selector = loader.case_selector();
    let mut deferred_files = BTreeMap::new();
    let mut prepared_scopes = BTreeMap::new();
    let mut eager_source_facts = BTreeMap::new();
    for (index, case) in cases.values().enumerate() {
        let cleanup = lifecycle_cleanup::load_refs(&case.dir).await?;
        connect_failures
            .load(
                &case.id,
                &case.dependencies_path,
                &mut resources.targets,
                &providers,
            )
            .await?;
        let case_index = if lazy && source_inventory_id.is_some() {
            let path = case.dependencies_path.clone();
            tokio::task::spawn_blocking(move || {
                crate::dependency_index::recorded_case_for_replay(&path)
            })
            .await
            .context("recorded Case fragment read failed")??
        } else {
            None
        };
        if lazy && (source_inventory_id.is_none() || case_index.is_some()) {
            let path = case.dependencies_path.clone();
            let cache = resources.reader.clone();
            let selector = case_selector.clone();
            let index_providers = providers.clone();
            let (file_index, startup, shared_lines, source_bytes) =
                tokio::task::spawn_blocking(move || -> Result<_> {
                    let mut index = match case_index {
                        Some(index) => index,
                        None => crate::dependency_index::load_file_for_replay(&path)?,
                    };
                    let mut cache = cache
                        .lock()
                        .map_err(|_| anyhow!("dependency cache lock poisoned"))?;
                    let records = P::SourceLoader::startup_records(&path, &index, &mut cache)?;
                    native::extend_index(&index_providers, &path, &mut index, &mut cache)?;
                    let shared_lines =
                        P::SourceLoader::shared_source_lines(&path, &index, &mut cache, &selector)?;
                    let source_bytes = crate::dependency_index::scoped::selected_bytes(&path)?;
                    Ok((index, records, shared_lines, source_bytes))
                })
                .await
                .context("case startup index task failed")??;
            deferred::register_index_targets(&file_index, &mut resources.targets, &providers)?;
            let mut skip: BTreeSet<_> = startup.iter().map(|(line, _)| *line).collect();
            skip.extend(shared_lines);
            loader.register_source(
                dependencies::SourceBatch {
                    path: &case.dependencies_path,
                    records: startup,
                    skip: &BTreeSet::new(),
                    source: ReplaySource::Case,
                    case: Some(&case.id),
                    process_rules: process_owned_dependencies,
                    cleanup: &cleanup,
                },
                &mut resources,
            )?;
            deferred_files.insert(
                case.id.clone(),
                deferred::CaseInventory {
                    index: Arc::new(file_index),
                    source_bytes,
                    skip,
                    cleanup,
                },
            );
        } else {
            let dependencies::SourceRecords {
                records,
                scope,
                facts,
            } = dependencies::read_dependency_file::<P::SourceRecord>(&case.dependencies_path)
                .await?;
            let source_directory =
                crate::dependency_index::scoped::case_directory(&case.dependencies_path)?;
            let cleanup = lifecycle_cleanup::load_refs(&source_directory).await?;
            loader.register_source(
                dependencies::SourceBatch {
                    path: &case.dependencies_path,
                    records,
                    skip: &BTreeSet::new(),
                    source: ReplaySource::Case,
                    case: Some(&case.id),
                    process_rules: process_owned_dependencies,
                    cleanup: &cleanup,
                },
                &mut resources,
            )?;
            prepared_scopes.insert(case.id.clone(), scope);
            eager_source_facts.insert(case.id.clone(), facts);
        }
        loader.load_case_metadata(&case.dir, &mut resources).await?;
        let loaded_cases = index + 1;
        let progress_percent = loaded_cases.saturating_mul(100) / total_cases.max(1);
        if progress_percent >= next_progress_percent || loaded_cases == total_cases {
            info!(
                loaded_cases,
                total_cases,
                progress_percent,
                case_source = %root_dir.display(),
                "loading replay case dependencies"
            );
            next_progress_percent = (progress_percent / 5 + 1).saturating_mul(5);
        }
    }
    let (loader, resources) = loader
        .prepare(
            SourcePreparation {
                root: root_dir.clone(),
                cases: cases.clone(),
                rules: process_owned_dependencies.to_vec(),
                lazy,
            },
            resources,
        )
        .await?;
    let SourceResources {
        mut native,
        mut targets,
        reader,
    } = resources;
    native.tls = Some(Arc::new(crate::tls::ServerTls(ca.clone())));
    let known_targets = targets.clone();
    let recording_network =
        network_access::apply_recorded_network_contract(&root_dir, &mut targets)?;
    let targets = assign_fake_ips(targets, fake_cidr)?;
    let occupied_fake_ips = targets.iter().map(|target| target.fake_ip).collect();
    let session_id = Uuid::new_v4();
    let witness_policy = replay_policy
        .as_ref()
        .map(|policy| policy.fingerprint().to_owned())
        .unwrap_or_else(|| crate::policy_evidence::digest(b"native-strict-request-evidence/v1"));
    let witness_policy = if providers.bindings().is_empty() {
        witness_policy
    } else {
        crate::policy_evidence::digest(&serde_json::to_vec(&(
            witness_policy,
            providers.bindings().signature()?,
        ))?)
    };
    let witnesses = crate::policy_evidence::WitnessStore::new_bound(
        &replay_artifact_dir,
        &session_id.to_string(),
        &witness_policy,
    )?;
    let key_context =
        crate::dependency_index::recording::root(&root_dir).unwrap_or_else(|| root_dir.clone());
    let target_observations = target_observation::TargetObservations::new(
        witnesses.clone(),
        session_id,
        key_context,
        witness_policy,
    );
    if let Some(policy) = &mut replay_policy {
        policy
            .contracts_mut()
            .configure_pre_match(lifecycle.pre_match);
        loader.register_policy_sources(policy)?;
        policy
            .contracts_mut()
            .configure_witnesses(witnesses, !lazy)?;
        loader.observe_policy_sources(policy)?;
    }
    let protocols = loader.finish(lazy, target_observations.clone(), replay_policy.as_ref());
    let deferred = lazy.then(|| {
        Arc::new(deferred::DeferredDependencies::new(
            deferred_files,
            reader,
            process_owned_dependencies.to_vec(),
            lifecycle.dependency_loading.case_timeout_seconds,
            lifecycle.dependency_loading.cache_bytes,
            known_targets,
        ))
    });
    let regular_policy_identity = report::global_evidence::preparation::policy_identity(
        process_owned_dependencies,
        replay_policy
            .as_ref()
            .map(|policy| policy.fingerprint().to_owned())
            .as_deref(),
    )?;
    let regular_report = config
        .report_path
        .clone()
        .unwrap_or_else(|| replay_artifact_dir.join("replay-report.json"));
    native.install_contracts(
        replay_policy
            .as_ref()
            .map(|policy| policy.contracts().native_rules())
            .unwrap_or_else(|| crate::value_extensions::strict_values()),
    )?;
    let mut state = RuntimeState {
        providers,
        native,
        admission_epoch: 0,
        timers,
        case_execution_plans: BTreeMap::new(),
        sequence_catalog,
        active_sequence: None,
        run_sequence: None,
        sequence_missing: Vec::new(),
        batch_scope: attribution.batch_scope,
        startup_phase: Default::default(),
        dependency_attribution_snapshot: attribution.snapshot,
        prepared_socketio_input: None,
        input_timing: None,
        primary_close_timing: None,
        stream_timing: lifecycle.stream_timing,
        stream_interval_cap_ms: lifecycle.stream_interval_cap_ms,
        target_observations,
        case_cleanup: Default::default(),
        target_stop_prepared: BTreeSet::new(),
        target_session_stopped: false,
        deferred,
        source_inventory_id,
        eager_source_facts,
        egress_counter_reader: None,
        egress_counter_starts: BTreeMap::new(),
        egress_rejections: BTreeMap::new(),
        session_id,
        started_at: Utc::now(),
        finalized_at: None,
        dns_listen,
        tcp_listen,
        mode,
        root_dir,
        cases,
        active_case_id,
        dependency_tails: control::dependency_tail::CaseTails::default()
            .with_async_rules(
                replay_policy
                    .as_ref()
                    .map(ReplayPolicy::async_rules)
                    .unwrap_or_default(),
                lifecycle.request_timeout,
            )
            .with_no_progress_timeout(lifecycle.case_no_progress_timeout),
        connect_failures,
        case_dependency_post_response_window: lifecycle.case_dependency_post_response_window,
        global_path,
        regular_global: BTreeMap::new(),
        targets,
        replay_policy,
        protocols,
        ca_cert_path,
        recording_network_path: Some(recording_network.path),
        recorded_dns_only_domains: recording_network.dns_only_domains,
        fake_cidr,
        unrecorded_domain_ips: BTreeMap::new(),
        unrecorded_ip_domains: BTreeMap::new(),
        occupied_fake_ips,
        next_unrecorded_fake_offset: 1,
        unrecorded_targets: Vec::new(),
        unrecorded_case_ids: BTreeSet::new(),
    };
    // Run-owned inventories are ready before Target startup, including lazy sessions.
    state.prepare_native_candidates();
    state.prepare_run_sequence()?;
    state.attach_run_sequence();
    for (case, source) in prepared_scopes {
        state.install_case_execution_plan(&case, source)?;
    }

    state.initialize_startup_phase();
    state
        .protocols
        .initialize_connections(state.active_case_id.as_deref());
    let state = tokio::task::spawn_blocking(move || -> Result<_> {
        report::global_evidence::regular::initialize(
            &mut state,
            &regular_report,
            &regular_policy_identity,
        )?;
        Ok(state)
    })
    .await
    .context("Global report inventory preparation failed")??;
    let state = Arc::new(Mutex::new(state));
    P::start(state.clone());
    Ok(LoadedRuntime {
        state,
        ca,
        report_path: config.report_path,
        session_path: config.session_path,
        control_socket_path: config.control_socket_path,
    })
}
