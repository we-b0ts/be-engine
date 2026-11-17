//! Projection of immutable inventory and session-owned consumption into reports.
use super::*;

impl<P: ReplayProtocolSet> RuntimeState<P> {
    pub(crate) fn snapshot_report(&self) -> ReplayReport<P::ReportSnapshot> {
        let mut report = ReplayReport {
            dependency_protocols: self.native.snapshot(),
            dependency_sequence_missing: self.sequence_missing.clone(),
            batch_reconciliation: None,
            startup_phase: self.startup_phase.report(),
            dependency_attribution_snapshot: self.dependency_attribution_snapshot.clone(),
            dependency_hypothesis_attempts: self
                .replay_policy
                .as_ref()
                .map(|p| p.contracts().hypothesis_attempts())
                .unwrap_or_default(),
            dependency_hypothesis_coverage_error: self
                .replay_policy
                .as_ref()
                .and_then(|p| p.contracts().hypothesis_coverage_error()),
            dependency_hypothesis_journal: self
                .replay_policy
                .as_ref()
                .and_then(|p| p.contracts().hypothesis_journal_manifest()),
            dependency_pre_matches: self
                .replay_policy
                .as_ref()
                .map(|p| p.contracts().pre_match_reports())
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
            ca_cert_path: self.ca_cert_path.display().to_string(),
            replay_policy: self.replay_policy.as_ref().map(ReplayPolicy::report),
            native: P::snapshot_report(self),
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

    pub(crate) fn case_reports(&self) -> Vec<ReplayCaseReport> {
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
                    .and_then(|policy| policy.contracts().request_times(&case.id).source),
                target_request_started_at: self
                    .replay_policy
                    .as_ref()
                    .and_then(|policy| policy.contracts().request_times(&case.id).target),
            })
            .collect()
    }
}
