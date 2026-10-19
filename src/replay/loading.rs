//! Replay startup inventory construction.
use super::*;

impl ReplayRuntime {
    #[cfg(test)]
    pub(super) async fn load(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
    ) -> Result<Self> {
        Self::load_with_lifecycle(
            config,
            dns_listen,
            tcp_listen,
            ReplayLifecycleConfig::default(),
        )
        .await
    }

    pub(super) async fn load_with_lifecycle(
        config: ReplayConfig,
        dns_listen: SocketAddr,
        tcp_listen: SocketAddr,
        lifecycle: ReplayLifecycleConfig,
    ) -> Result<Self> {
        lifecycle.dependency_loading.validate()?;
        let lazy = lifecycle.dependency_loading.lazy_cases;
        clear_report_artifacts(config.report_path.as_deref()).await?;
        let root_dir = config.case_dir;
        let process_owned_dependencies = &config.process_owned_dependencies;
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
        let ca = Arc::new(MitmCa::load_or_generate(&ca_cert_path, &ca_key_path)?);
        let (global_path, global_debug_path) = find_run_level_dependencies(&root_dir);
        let global_report_stamp = global_path
            .as_ref()
            .map(|path| crate::dependency_index::FileStamp::read(path))
            .transpose()?;
        let mut mysql = MysqlReplayState::default();
        let mut http_exchanges = Vec::new();
        let mut http_events = http::HttpReplayEvents::default();
        let mut http_blackholes = Vec::new();
        let mut redis = redis::RedisReplayState::default();
        let mut memcached = memcached::MemcachedReplayState::default();
        let mut kafka = kafka::KafkaReplayState::default();
        let mut motan = motan::MotanReplayState::default();
        let mut targets = BTreeMap::new();
        let mut connection_identities = HashMap::new();
        let reader = Arc::new(std::sync::Mutex::new(
            crate::dependency_index::RecordReader::new(lifecycle.dependency_loading.cache_bytes),
        ));
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

        if let Some(path) = &global_path {
            global::load(
                path,
                &mut mysql,
                &mut http_exchanges,
                &mut http_blackholes,
                &mut redis,
                &mut memcached,
                &mut kafka,
                &mut motan,
                &mut targets,
                &mut connection_identities,
                process_owned_dependencies,
                reader.clone(),
            )
            .await?;
        }
        // Source-owned Global slots are stable across selected APIs. Later
        // Case-derived Global aliases remain small session-specific evidence.
        global_source::freeze(
            &mut mysql,
            &mut http_events,
            http_exchanges.len(),
            &mut redis,
            &mut memcached,
            &mut kafka,
            &mut motan,
        );
        if let Some(path) = global_debug_path {
            load_motan_debug_file(&path, &mut motan, &mut targets).await?;
        }
        let shared_http_keys: BTreeSet<_> = config
            .policy_path
            .as_deref()
            .map(policy::http_cross_case_rules)
            .transpose()?
            .unwrap_or_default()
            .iter()
            .map(|(_, s)| crate::dependency_index::http_key(&s.host, s.port, &s.method, &s.path))
            .collect();
        let mut deferred_files = BTreeMap::new();
        for (index, case) in cases.values().enumerate() {
            if lazy {
                let path = case.dependencies_path.clone();
                let cache = reader.clone();
                let (file_index, startup) = tokio::task::spawn_blocking(move || -> Result<_> {
                    let index = crate::dependency_index::load_file(&path)?;
                    let records = deferred::startup_records(
                        &path,
                        &index,
                        &mut *cache
                            .lock()
                            .map_err(|_| anyhow!("dependency cache lock poisoned"))?,
                    )?;
                    Ok((index, records))
                })
                .await
                .context("case startup index task failed")??;
                deferred::register_index_targets(&file_index, &mut targets)?;
                let mut skip: BTreeSet<_> = startup.iter().map(|(line, _)| *line).collect();
                skip.extend(
                    file_index
                        .http
                        .iter()
                        .filter(|entry| shared_http_keys.contains(&entry.key))
                        .map(|entry| entry.location.line),
                );
                dependencies::register_dependency_records(
                    &case.dependencies_path,
                    startup,
                    &BTreeSet::new(),
                    ReplaySource::Case,
                    Some(&case.id),
                    &mut mysql,
                    &mut http_exchanges,
                    &mut http_blackholes,
                    &mut redis,
                    &mut memcached,
                    &mut kafka,
                    &mut motan,
                    &mut targets,
                    &mut connection_identities,
                    process_owned_dependencies,
                )?;
                deferred_files.insert(
                    case.id.clone(),
                    deferred::CaseInventory {
                        index: file_index,
                        skip,
                    },
                );
            } else {
                load_dependency_file(
                    &case.dependencies_path,
                    ReplaySource::Case,
                    Some(&case.id),
                    &mut mysql,
                    &mut http_exchanges,
                    &mut http_blackholes,
                    &mut redis,
                    &mut memcached,
                    &mut kafka,
                    &mut motan,
                    &mut targets,
                    &mut connection_identities,
                    process_owned_dependencies,
                )
                .await?;
            }
            load_motan_debug_file(
                &case.dir.join("dependencies-debug.jsonl"),
                &mut motan,
                &mut targets,
            )
            .await?;
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
        let shared_root = root_dir.clone();
        let shared_policy = config.policy_path.clone();
        let shared_cases = if lazy { BTreeMap::new() } else { cases.clone() };
        let (http_exchanges, mut targets) = tokio::task::spawn_blocking(move || -> Result<_> {
            http_cross_case::load(
                &shared_root,
                shared_policy.as_deref(),
                &shared_cases,
                &mut http_exchanges,
                &mut targets,
            )?;
            Ok((http_exchanges, targets))
        })
        .await
        .context("HTTP cross-case preload task failed")??;
        let http_case_exchange_index = http::case_exchange_index(&http_exchanges);
        let mysql_root = root_dir.clone();
        let mysql_rules = process_owned_dependencies.to_vec();
        let mysql_cases = cases.keys().cloned().collect();
        let mysql = tokio::task::spawn_blocking(move || -> Result<_> {
            mysql.set_origins(
                mysql::ownership::load(&mysql_root, &mysql_rules)?,
                &mysql_cases,
            );
            Ok(mysql)
        })
        .await
        .context("MySQL transaction ownership preparation failed")??;
        let redis_root = root_dir.clone();
        let redis_policy = config.policy_path.clone();
        let redis_cases = cases.clone();
        let redis_process_rules = process_owned_dependencies.to_vec();
        let subscription_reader = reader.clone();
        let (mut redis, mut targets) = tokio::task::spawn_blocking(move || -> Result<_> {
            redis.resolve_pubsub_subscriptions(
                &redis_root,
                &mut targets,
                &redis_process_rules,
                subscription_reader,
            )?;
            // Eager and lazy loading have registered all selected Redis lanes.
            // Apply ownership proof before any target request can be admitted.
            redis.apply_api_origin_order(&redis_root, &redis_process_rules)?;
            redis::load_cross_case(
                &mut redis,
                &redis_root,
                redis_policy.as_deref(),
                &redis_cases,
                &mut targets,
                &redis_process_rules,
            )?;
            Ok((redis, targets))
        })
        .await
        .context("Redis cross-case preload task failed")??;
        redis.apply_snapshot_overlays(&root_dir, process_owned_dependencies);

        let known_targets = targets.clone();
        let recording_network_path =
            network_access::apply_recorded_endpoint_allowlist(&root_dir, &mut targets)?;
        let targets = assign_fake_ips(targets, fake_cidr)?;
        let occupied_fake_ips = targets.iter().map(|target| target.fake_ip).collect();
        if let Some(case_id) = &active_case_id
            && let Some(case) = cases.get_mut(case_id)
        {
            case.status = ReplayCaseStatus::Active;
        }

        let http_ignore_query_params = config
            .http_ignore_query_params
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let session_id = Uuid::new_v4();
        let mut replay_policy = config
            .policy_path
            .as_deref()
            .map(|path| ReplayPolicyRuntime::load_with_sources(path, &cases, !lazy))
            .transpose()?;
        if let Some(policy) = &mut replay_policy {
            let witnesses = crate::policy_evidence::WitnessStore::new_bound(
                &replay_artifact_dir,
                &session_id.to_string(),
                &policy.report().fingerprint,
            )?;
            policy
                .request_contracts
                .configure_witnesses(witnesses, !lazy)?;
            for (index, exchange) in mysql
                .exchanges
                .iter()
                .enumerate()
                .filter(|(_, exchange)| exchange.source == ReplaySource::Case)
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
                    Some(index),
                );
            }
            http::observe_recorded_policy_exchanges(policy, &http_exchanges);
            memcached::observe_recorded_policy_exchanges(policy, &memcached);
            redis.value_rules = policy.redis_value_rules();
            redis.dynamic_values = policy.dynamic_values.clone();
            redis.request_contracts = policy.request_contracts.clone();
            redis.configure_lock_tokens(&policy.redis_lock_token_rules());
            redis.configure_publish(policy.redis_publish_rules());
            redis.configure_time_shift(&policy.redis_time_shift_rules())?;
            policy.reject_http_ignore_overlap(&http_ignore_query_params)?;
        }

        let deferred = lazy.then(|| {
            Arc::new(deferred::DeferredDependencies::new(
                deferred_files,
                reader,
                connection_identities,
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
                .map(|policy| policy.report().fingerprint)
                .as_deref(),
        )?;
        let regular_report = config
            .report_path
            .clone()
            .unwrap_or_else(|| replay_artifact_dir.join("replay-report.json"));
        let mut state = ReplayState {
            deferred,
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
            case_dependency_post_response_window: lifecycle.case_dependency_post_response_window,
            global_path,
            regular_global: BTreeMap::new(),
            targets,
            mysql,
            http_exchanges,
            http_case_exchange_index,
            http_blackholes,
            redis,
            memcached,
            kafka,
            motan,
            http_events,
            ca_cert_path,
            replay_policy,
            http_ignore_query_params,
            allowed_unused_http: config.allowed_unused_http,
            recording_network_path: Some(recording_network_path),
            fake_cidr,
            unrecorded_domain_ips: BTreeMap::new(),
            unrecorded_ip_domains: BTreeMap::new(),
            occupied_fake_ips,
            next_unrecorded_fake_offset: 1,
            unrecorded_targets: Vec::new(),
            unrecorded_case_ids: BTreeSet::new(),
        };
        let state = tokio::task::spawn_blocking(move || -> Result<_> {
            if let (Some(source), Some(expected)) = (&state.global_path, &global_report_stamp) {
                ensure!(
                    crate::dependency_index::FileStamp::read(source)? == *expected,
                    "Global Source changed before report projection preparation"
                );
            }
            report::global_evidence::regular::initialize(
                &mut state,
                &regular_report,
                &regular_policy_identity,
            )?;
            if let (Some(source), Some(expected)) = (&state.global_path, &global_report_stamp) {
                ensure!(
                    crate::dependency_index::FileStamp::read(source)? == *expected,
                    "Global Source changed while preparing report projection"
                );
            }
            Ok(state)
        })
        .await
        .context("Global report inventory preparation failed")??;
        let runtime = Self {
            state: Arc::new(Mutex::new(state)),
            ca,
            report_path: config.report_path,
            session_path: config.session_path,
            control_socket_path: config.control_socket_path,
        };
        // A single-directory Replay starts with an implicit active case.
        let initial_case = runtime.state.lock().await.active_case_id.clone();
        if let Some(case_id) = initial_case {
            deferred::prepare_case(runtime.state.clone(), &case_id).await?;
        }
        Ok(runtime)
    }
}
