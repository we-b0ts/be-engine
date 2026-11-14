//! Native Memcached hooks for the shared observe/select/wait execution engine.
use super::*;
use crate::replay::admission::{
    RequestAdmission,
    request::{DependencyRequestAdapter, WaitDependency, execute},
};

const DELIVERY_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

struct NativeRequest<'a> {
    target: &'a TargetKey,
    wire: MemcachedWireProtocol,
    request: &'a MemcachedRequest,
}

enum Rejection {
    Unsupported,
    Native(CommandMatchDiagnostic),
    CommitFailed,
}

pub(super) async fn match_memcached_request(
    shared: &Arc<Mutex<ReplayState>>,
    target: &TargetKey,
    wire: MemcachedWireProtocol,
    request: &MemcachedRequest,
) -> Option<MatchedMemcachedExchange> {
    execute(
        shared,
        &mut NativeRequest {
            target,
            wire,
            request,
        },
        tokio::time::Instant::now() + DELIVERY_WAIT,
    )
    .await
    .ok()
}

impl DependencyRequestAdapter<ReplayState> for NativeRequest<'_> {
    type Matched = MatchedMemcachedExchange;
    type Error = Rejection;

    fn observe_once(&mut self, state: &mut ReplayState) -> RequestAdmission {
        let case = state.active_case_id.clone();
        let event = state
            .protocols
            .memcached
            .events
            .request_order
            .reserve(case.as_deref());
        let observed_at = Utc::now();
        let observation = if memcached_is_unsupported(self.request) {
            None
        } else {
            matching::observe_request(MemcachedMatchContext {
                active_case_id: case.as_deref(),
                target: self.target,
                wire_protocol: self.wire,
                request: self.request,
                policy: state.replay_policy.as_ref(),
                observed_at,
            })
        };
        RequestAdmission::capture(
            state,
            Some(event),
            Some(observed_at),
            observation,
            observation.is_some(),
        )
    }

    fn try_select(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
    ) -> std::result::Result<Self::Matched, Self::Error> {
        if memcached_is_unsupported(self.request) {
            return Err(Rejection::Unsupported);
        }
        let ReplayState {
            protocols,
            replay_policy,
            ..
        } = state;
        protocols
            .memcached
            .select_memcached(
                MemcachedMatchContext {
                    active_case_id: observation.case.as_deref(),
                    target: self.target,
                    wire_protocol: self.wire,
                    request: self.request,
                    policy: replay_policy.as_ref(),
                    observed_at: observation
                        .observed_at
                        .expect("native observation captures request time"),
                },
                observation.observation_id,
            )
            .map_err(Rejection::Native)
    }

    fn wait_dependency<'a>(
        &self,
        state: &'a ReplayState,
        _observation: &RequestAdmission,
        error: &Self::Error,
    ) -> Option<WaitDependency<'a>> {
        let Rejection::Native(CommandMatchDiagnostic::LaneBlocked { blocked_by, .. }) = error
        else {
            return None;
        };
        let index = state
            .protocols
            .memcached
            .exchanges
            .iter()
            .position(|exchange| {
                exchange.source == blocked_by.source
                    && exchange.case_id == blocked_by.case_id
                    && exchange.record.connection_id == blocked_by.connection_id
                    && exchange.record.sequence == blocked_by.sequence
            })?;
        Some(WaitDependency::slot(
            &state.protocols.memcached.lifecycle,
            index,
            Barrier::Delivered,
        ))
    }

    fn interrupted(&self, reason: &'static str) -> Self::Error {
        Rejection::Native(CommandMatchDiagnostic::EvidenceUnavailable {
            reason: reason.into(),
        })
    }

    fn on_selected(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
        matched: &mut Self::Matched,
    ) -> std::result::Result<(), Self::Error> {
        matched.report.target_event_index = observation.event_index;
        if let Some(policy) = &mut state.replay_policy
            && let Err(error) =
                policy.commit(observation.case.as_deref(), matched.policy_decision.clone())
        {
            state.protocols.memcached.fail_exchange(
                matched,
                format!("Memcached request contract commit failed: {error:#}"),
            );
            return Err(Rejection::CommitFailed);
        }
        Ok(())
    }

    fn on_rejected(
        &mut self,
        state: &mut ReplayState,
        observation: &RequestAdmission,
        error: &Self::Error,
    ) {
        // A claimed request's commit failure already owns its finite failure
        // and unsafe report; it is not an unmatched physical request.
        if matches!(error, Rejection::CommitFailed) {
            return;
        }
        if let Some(case) = &observation.case {
            state
                .protocols
                .memcached
                .events
                .dirty_case_ids
                .insert(case.clone());
        }
        let unsupported = matches!(error, Rejection::Unsupported);
        let report = CommandRequestReport {
            target_observation_id: None,
            case_id: observation.case.clone(),
            target: self.target.clone(),
            command: self.request.command.clone(),
            target_event_index: observation.event_index,
            request_fingerprint: None,
            reason: if unsupported {
                "Memcached command mode is unsupported for replay"
            } else {
                "no recorded Memcached exchange matched target/protocol/arguments"
            }
            .into(),
            diagnostic: match error {
                Rejection::Native(diagnostic) => Some(diagnostic.clone()),
                _ => None,
            },
        };
        if unsupported {
            state.protocols.memcached.events.unsupported.push(report);
        } else {
            state.protocols.memcached.events.unmatched.push(report);
        }
    }
}
