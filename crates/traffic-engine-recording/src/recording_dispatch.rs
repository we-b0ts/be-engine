//! Native attribution adapters feed the common recording queue and failure handling.
use super::*;
use traffic_protocol::capture::CaptureEvidence;

impl AppState {
    #[allow(dead_code)]
    pub fn record_proxy_error(
        &self,
        event: crate::recorder::ProxyErrorEvent,
        targets: DependencyTargets,
    ) {
        self.record_event_for_targets(RecorderEvent::ProxyError(event), targets);
    }
    pub fn record_connect_failure(
        &self,
        event: crate::recorder::DependencyConnectFailureEvent,
        targets: DependencyTargets,
    ) {
        self.record_event_for_targets(RecorderEvent::DependencyConnectFailure(event), targets);
    }

    pub fn record_event(&self, event: RecorderEvent) {
        let targets = self.capture_dependency_targets();
        self.record_event_for_targets(event, targets);
    }

    pub fn record_event_for_targets(&self, event: RecorderEvent, mut targets: DependencyTargets) {
        if targets.process_rule_ids.is_empty() {
            let rules = self
                .inner
                .process_owned_dependencies
                .matching_capture_rules(&event);
            targets = crate::recorder::process_classification::classify(
                targets,
                rules,
                &self.config().process_dependency_tasks,
            );
        }
        let background_match = self.inner.process_owned_dependencies.matching_rule(&event);
        let (probe_attribution, suppress_default_global) = self.preflight_probe_attribution(&event);
        let background_attributed =
            probe_attribution.is_none() && !suppress_default_global && background_match.is_some();
        let api_idle = if targets.cases.is_empty() && !targets.bootstrap_open {
            self.inner
                .process_owned_dependencies
                .matching_api_candidate(&event)
        } else {
            None
        };
        let global_attribution = probe_attribution.or_else(|| {
            (!suppress_default_global)
                .then(|| {
                    targets
                        .process_owned_rule
                        .as_deref()
                        .or_else(|| background_match.as_ref().map(|matched| matched.rule_name()))
                        .map(|rule_name| crate::recorder::GlobalDependencyAttribution {
                            reason: "background_rule",
                            phase: if targets.bootstrap_open {
                                "bootstrap"
                            } else {
                                "runtime"
                            },
                            matched_by: rule_name.to_string(),
                        })
                })
                .flatten()
        });
        let global_attribution = global_attribution.or_else(|| {
            (!suppress_default_global)
                .then_some(api_idle)
                .flatten()
                .map(|name| crate::recorder::GlobalDependencyAttribution {
                    reason: "api_trigger_candidate",
                    phase: "runtime",
                    matched_by: name.to_string(),
                })
        });
        // A later callback can reference an idle RPC publisher. Preserve that
        // finite protocol witness alongside the callback even without a Case.
        let global_attribution = global_attribution.or_else(|| {
            (targets.cases.is_empty()
                && !suppress_default_global
                && !targets.bootstrap_open
                && targets.ambiguous_active_cases == 0
                && matches!(&event, RecorderEvent::RedisExchange(exchange)
                    if exchange.rpc_callback_capture.as_deref() == Some("bounded_window")))
            .then(|| crate::recorder::GlobalDependencyAttribution {
                reason: "rpc_publisher",
                phase: "runtime",
                matched_by: "socketio_rpc_protocol".to_owned(),
            })
        });
        self.inner.active_cases.observe_async_dependency_event(
            &event,
            &targets,
            global_attribution.is_none(),
        );
        self.inner.active_cases.observe_stream_tail_event(
            &event,
            &targets,
            global_attribution.is_none(),
        );
        let enqueued =
            self.enqueue_capture(event, targets, global_attribution, suppress_default_global);
        if enqueued.is_ok()
            && background_attributed
            && let Some(matched) = &background_match
        {
            self.inner
                .process_owned_dependencies
                .record_completed_match(matched);
        }
    }

    fn preflight_probe_attribution(
        &self,
        event: &RecorderEvent,
    ) -> (Option<crate::recorder::GlobalDependencyAttribution>, bool) {
        let Some(kind) = self.inner.preflight_probe else {
            return (None, false);
        };
        let Some(successful) = kind.classify_recording_event(event) else {
            return (None, false);
        };
        if !successful
            || self
                .inner
                .preflight_probe_recorded
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return (None, true);
        }
        (
            Some(crate::recorder::GlobalDependencyAttribution {
                reason: "preflight_probe",
                phase: "runtime",
                matched_by: kind.matched_by().to_string(),
            }),
            true,
        )
    }

    pub fn enqueue_capture(
        &self,
        event: impl CaptureEvidence,
        targets: DependencyTargets,
        global_attribution: Option<crate::recorder::GlobalDependencyAttribution>,
        suppress_default_global: bool,
    ) -> Result<()> {
        let event_type = event.event_type();
        let target_case_ids: Vec<_> = targets.cases.iter().map(|(case, _)| case.id).collect();
        match self.recorder().try_record_event(
            event,
            targets,
            global_attribution,
            suppress_default_global,
        ) {
            Err(err) => {
                warn!(
                    error = %err,
                    event_type,
                    "failed to enqueue recorder event"
                );
                let invalidation = CaseInvalidation::new(
                    "recording_writer_failure",
                    format!("failed to enqueue {event_type} recorder event: {err}"),
                );
                let invalidated = if target_case_ids.is_empty() {
                    self.inner
                        .active_cases
                        .invalidate_current_case(invalidation)
                        .into_iter()
                        .collect()
                } else {
                    target_case_ids
                        .into_iter()
                        .filter_map(|id| {
                            self.inner
                                .active_cases
                                .invalidate_case(id, invalidation.clone())
                        })
                        .collect::<Vec<_>>()
                };
                for case in invalidated {
                    warn!(
                        case_id = %case.id,
                        rule = %case.rule_name,
                        "active recording case invalidated by recorder writer failure"
                    );
                }
                Err(err)
            }
            Ok(()) => Ok(()),
        }
    }
}
