//! Projection of immutable inventory and session-owned consumption into reports.
use super::*;

impl ReplayState {
    pub(super) fn snapshot_report(&self) -> ReplayReport {
        let unused_case_http_exchanges = self.unused_http_exchanges(ReplaySource::Case, false);
        let allowed_unused_case_http_exchanges =
            self.unused_http_exchanges(ReplaySource::Case, true);
        let mut report = ReplayReport {
            dependency_protocols: self.native.snapshot(),
            dependency_sequence_missing: self.sequence_missing.clone(),
            batch_reconciliation: None,
            startup_phase: self.startup_phase.report(),
            http_ingress: self.http_ingress.report(),
            dependency_attribution_snapshot: self.dependency_attribution_snapshot.clone(),
            dependency_hypothesis_attempts: self
                .replay_policy
                .as_ref()
                .map(|p| p.request_contracts.hypothesis_attempts())
                .unwrap_or_default(),
            dependency_hypothesis_coverage_error: self
                .replay_policy
                .as_ref()
                .and_then(|p| p.request_contracts.hypothesis_coverage_error()),
            dependency_hypothesis_journal: self
                .replay_policy
                .as_ref()
                .and_then(|p| p.request_contracts.hypothesis_journal_manifest()),
            dependency_pre_matches: self
                .replay_policy
                .as_ref()
                .map(|p| p.request_contracts.pre_match_reports())
                .unwrap_or_default(),
            case_execution_failures: self.dependency_tails.failures(),
            connect_failures: self.connect_failures.snapshot(),
            policy_witnesses: self.target_observations.manifest(),
            target_observation_coverage_error: self.target_observations.coverage_error(),
            target_observation_key_context: self.target_observations.key_context().to_owned(),
            target_observation_policy_fingerprint: self
                .target_observations
                .policy_fingerprint()
                .into(),
            egress_rejections: self.egress_rejections.values().cloned().collect(),
            version: 7,
            mysql_transaction_semantics: MYSQL_TRANSACTION_SEMANTICS,
            session_id: self.session_id.to_string(),
            started_at: self.started_at,
            finalized_at: self.finalized_at,
            finalized: self.finalized_at.is_some(),
            mode: self.mode,
            dns_listen: self.dns_listen.to_string(),
            tcp_listen: self.tcp_listen.to_string(),
            case_dir: self.root_dir.display().to_string(),
            case_dependencies_path: self
                .cases
                .values()
                .next()
                .map(|case| case.dependencies_path.display().to_string())
                .unwrap_or_default(),
            active_case_id: self.active_case_id.clone(),
            cases: self.case_reports(),
            selected_case_ids: self.cases.keys().cloned().collect(),
            global_dependencies_path: self
                .global_path
                .as_ref()
                .map(|path| path.display().to_string()),
            recording_network_path: self
                .recording_network_path
                .as_ref()
                .map(|path| path.display().to_string()),
            targets: self.targets.clone(),
            unrecorded_targets: self.unrecorded_targets.clone(),
            success_detail_limit: SUCCESS_DETAIL_LIMIT,
            success_detail_scope: SUCCESS_DETAIL_SCOPE,
            connections: self.mysql.events.connections,
            connection_events: self.mysql.events.connection_events.clone(),
            builtin_query_count: self.mysql.events.builtin_query_count,
            builtin_queries: self.mysql.events.builtin_queries.clone(),
            matched_query_count: self.mysql.events.matched_query_count,
            matched_queries: self.mysql.events.matched_queries.clone(),
            unmatched_queries: self.mysql.events.unmatched_queries.clone(),
            unsupported_commands: self.mysql.events.unsupported_commands.clone(),
            metadata_warnings: self.mysql.events.metadata_warnings.clone(),
            unused_global_exchanges: self.unused_exchanges(ReplaySource::Startup),
            unused_global_exchange_count: self.global_mysql_unused_count(),
            unused_case_exchanges: self.unused_exchanges(ReplaySource::Case),
            process_owned_mysql_exchanges: self.process_owned_mysql(),
            global_mysql_transaction_exchanges: self.global_mysql_transactions(),
            allowed_unused_mysql_rollback_exchanges: self.allowed_unused_rollbacks(),
            allowed_unused_mysql_commit_exchanges: self.allowed_unused_commits(),
            allowed_unused_mysql_autocommit_exchanges: self.allowed_unused_autocommit(),
            allowed_unused_mysql_connection_read_committed_exchanges: self
                .allowed_unused_connection_read_committed(),
            transaction_equivalent_mysql_autocommit_exchanges: self
                .transaction_equivalent_autocommit(),
            mysql_isolation_equivalence: self.mysql.isolation.audit(),
            matched_http_exchange_count: self.http_events.matched_count,
            cancelled_http_streams: self.http_events.cancelled.values().cloned().collect(),
            matched_http_exchanges: self.http_events.matched.clone(),
            unmatched_http_requests: self.http_events.unmatched.clone(),
            unsupported_http_exchanges: self.http_events.unsupported.clone(),
            http_request_header_mismatches: self.http_events.header_mismatches.clone(),
            http_request_header_observations: self.http_events.header_observations.clone(),
            http_request_header_observation_count: self.http_events.header_observation_count,
            unused_global_http_exchanges: self.unused_http_exchanges(ReplaySource::Startup, false),
            unused_global_http_exchange_count: self.global_http_unused_count(),
            unused_case_http_exchanges,
            allowed_unused_case_http_exchanges,
            protocols: ProtocolsReport {
                redis: self.redis.snapshot(),
                memcached: self.memcached.snapshot(),
                kafka: self.kafka.snapshot(),
                motan: self.motan.snapshot(),
            },
            ca_cert_path: self.ca_cert_path.display().to_string(),
            replay_policy: self.replay_policy.as_ref().map(ReplayPolicyRuntime::report),
            http_ignored_query_params: self.http_ignore_query_params.clone(),
            allowed_unused_http: self.allowed_unused_http.as_ref().map(|config| {
                ReplayAllowedUnusedHttpReport {
                    config: config.config_path.display().to_string(),
                    hosts: config.hosts.iter().cloned().collect(),
                }
            }),
        };
        report
            .case_execution_failures
            .extend(self.native.case_failures());
        if let Some(scope) = &self.batch_scope {
            if scope.unlocated_inventory_gap {
                for case in self.cases.keys() {
                    report.case_execution_failures.push(serde_json::json!({"case_id":case,
                        "kind":"source_inventory_gap","source":"sealed_source_inventory",
                        "reason":"Source recording has an unlocated inventory gap; the retained Case cannot establish complete dependency coverage"}));
                }
            }
            for (case, kinds) in &scope.inventory.unsupported_by_scope {
                if self.cases.contains_key(case) {
                    report.case_execution_failures.push(serde_json::json!({"case_id":case,"kind":"source_dependency_unsupported",
                        "source":"sealed_source_inventory","event_counts":kinds,"reason":"recorded mandatory dependencies have no complete supported Replay contract"}));
                }
            }
            report.batch_reconciliation = Some(scope.report(&report));
        }
        report
    }

    pub(super) fn case_reports(&self) -> Vec<ReplayCaseReport> {
        self.cases
            .values()
            .map(|case| ReplayCaseReport {
                case_id: case.id.clone(),
                case_dir: case.dir.display().to_string(),
                dependencies_path: case.dependencies_path.display().to_string(),
                status: case.status,
                source_request_started_at: self
                    .replay_policy
                    .as_ref()
                    .and_then(|policy| policy.request_contracts.request_times(&case.id).source),
                target_request_started_at: self
                    .replay_policy
                    .as_ref()
                    .and_then(|policy| policy.request_contracts.request_times(&case.id).target),
            })
            .collect()
    }
}
