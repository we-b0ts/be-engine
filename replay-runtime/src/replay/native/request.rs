use super::*;
use traffic_engine_replay::replay::native::diagnosis;
pub(super) use traffic_engine_replay::replay::native::request::*;
use traffic_replay::exchange::{MatchContext, Selection};
impl<P: ReplayProtocolSet> admission::request::DependencyRequestAdapter<RuntimeState<P>>
    for Request
{
    type Matched = Matched;
    type Error = Rejected;
    fn sequence_request_bytes(&self) -> Option<usize> {
        (!self.optional_control).then_some(self.bytes)
    }
    fn sequence_wait_allowed(&self, _: &RuntimeState<P>, error: &Rejected) -> bool {
        error.kind != RejectionKind::UnverifiedSession
    }

    fn observe_once(&mut self, state: &mut RuntimeState<P>) -> admission::RequestAdmission {
        let case = state.active_case_id.as_deref();
        let event = state.native.order.reserve(case);
        let id = Uuid::new_v4();
        let payload = self
            .message
            .evidence(&serde_json::json!({"kind":"request"}))
            .and_then(|value| Ok(serde_json::to_vec(&value)?));
        let retention = payload.and_then(|bytes| {
            state.target_observations.record(
                id,
                case,
                None,
                self.protocol.as_str(),
                self.observed,
                &bytes,
            )
        });
        let retained = state.target_observations.retained(&retention);
        admission::RequestAdmission::capture(
            state,
            Some(event),
            Some(self.observed),
            Some(id),
            retained,
        )
    }

    fn try_select(
        &mut self,
        state: &mut RuntimeState<P>,
        observation: &admission::RequestAdmission,
    ) -> Result<Matched, Rejected> {
        if let Some(reason) = observation.cancel_reason(state) {
            return Err(Rejected {
                reason: reason.into(),
                blocker: None,
                kind: RejectionKind::Other,
            });
        }
        if self
            .session_owner
            .as_ref()
            .and_then(|owner| owner.epoch)
            .is_some_and(|epoch| epoch != state.admission_epoch)
        {
            return Err(Rejected {
                reason: "native transaction crossed a Replay ownership boundary".into(),
                blocker: None,
                kind: RejectionKind::Other,
            });
        }
        let native = &state.native;
        let diagnostics = std::cell::RefCell::new(diagnosis::CandidateDiagnostics::default());
        let selected = native.core.select_observed(
            MatchContext {
                protocol: self.protocol,
                endpoint: &self.endpoint,
                active_case: observation.case.as_deref(),
                request: self.message.as_ref(),
                session: self.session,
                lane: self.lane.as_deref(),
                request_session: self.request_session.as_ref(),
                metadata: native.contracts.metadata(),
            },
            |exchange| native.clocks(exchange.index, self.observed, false),
            |exchange, comparison| {
                anyhow::ensure!(
                    self.session_owner.as_ref().is_none_or(|owner| {
                        owner.scope == exchange.source.source
                            && owner.case == exchange.source.case_id
                    }),
                    "native transaction continuation has a different Source owner"
                );
                identity(
                    native.contracts.as_ref(),
                    native,
                    exchange.index,
                    comparison,
                )
                .map(|_| ())
            },
            |exchange, comparison| {
                diagnostics
                    .borrow_mut()
                    .observe(native, exchange, self, comparison);
                Ok(())
            },
        );
        self.diagnostics = diagnostics.into_inner();
        let selected = selected?;
        let selected = match selected {
            Selection::Matched(selected) => selected,
            Selection::LaneBlocked { blocker, .. } => {
                return Err(Rejected {
                    reason: "recorded native connection predecessor has not reached its required barrier"
                        .into(),
                    blocker: Some(blocker),
                    kind: RejectionKind::Other,
                });
            }
            Selection::NotFound => {
                return Err(Rejected {
                    reason: "no recorded native request matched the active Source scope".into(),
                    blocker: None,
                    kind: RejectionKind::NoMatch,
                });
            }
            Selection::SessionUnverified => {
                return Err(Rejected {
                    reason: "recorded native transaction has incomplete Source continuity proof"
                        .into(),
                    blocker: None,
                    kind: RejectionKind::UnverifiedSession,
                });
            }
        };
        let index = selected.index;
        let request_identity = identity(
            native.contracts.as_ref(),
            native,
            index,
            &selected.comparison,
        )?;
        let delay = native.core.exchanges[index].native.response_delay;
        let run_owned = native.core.exchanges[index].source.source.is_run_owned();
        let storage = native.prepare_storage_delivery(index, self.message.as_ref());
        let ticket = match self.session {
            Some(owner) => state.native.core.claim_bound(index, owner)?,
            None => state.native.core.claim(index)?,
        };
        if let Err(error) = state
            .native
            .contracts
            .commit_comparison(selected.comparison, request_identity)
        {
            state.native.core.fail(index, &ticket);
            return Err(error.into());
        }
        Ok(Matched {
            index,
            ticket,
            observed: self.observed,
            delay,
            case: observation.case.clone(),
            epoch: state.admission_epoch,
            run_owned,
            storage,
        })
    }

    fn wait_dependency<'a>(
        &self,
        state: &'a RuntimeState<P>,
        _: &admission::RequestAdmission,
        error: &Rejected,
    ) -> Option<admission::request::WaitDependency<'a>> {
        let blocker = error.blocker?;
        let barrier = if state.native.core.exchanges[blocker].source.source == ReplaySource::Case {
            admission::Barrier::Admitted
        } else {
            admission::Barrier::Delivered
        };
        Some(admission::request::WaitDependency::slot(
            &state.native.core.lifecycle,
            blocker,
            barrier,
        ))
    }

    fn interrupted(&self, reason: &'static str) -> Rejected {
        Rejected {
            reason: reason.into(),
            blocker: None,
            kind: RejectionKind::Other,
        }
    }

    fn on_rejected(
        &mut self,
        state: &mut RuntimeState<P>,
        observation: &admission::RequestAdmission,
        error: &Rejected,
    ) {
        if self.optional_control && error.kind == RejectionKind::NoMatch {
            return;
        }
        state.native.record_failure(
            self.protocol,
            &self.endpoint,
            observation.case.clone(),
            observation.event_index,
            observation.observation_id,
            &error.reason,
            self.diagnostics.clone(),
        );
    }
}
