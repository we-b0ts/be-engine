//! Native requests enter the common observe/select/wait/commit execution loop.
use super::*;
use traffic_contract::{compare::Comparison, identity::IdentityDecision};
use traffic_protocol::message::ProtocolMessage;
use traffic_replay::exchange::{MatchContext, Selection};

pub(super) struct Request {
    pub protocol: ProtocolId,
    pub endpoint: Endpoint,
    pub message: Arc<dyn ProtocolMessage>,
    pub observed: DateTime<Utc>,
    pub bytes: usize,
}

pub(super) struct Matched {
    pub index: usize,
    pub ticket: admission::ClaimTicket,
    pub observed: DateTime<Utc>,
    pub delay: std::time::Duration,
    pub case: Option<String>,
    pub epoch: u64,
    pub run_owned: bool,
}

pub(super) struct Rejected {
    reason: String,
    blocker: Option<usize>,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}
impl std::fmt::Debug for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}
impl std::error::Error for Rejected {}
impl From<anyhow::Error> for Rejected {
    fn from(error: anyhow::Error) -> Self {
        Self {
            reason: error.to_string(),
            blocker: None,
        }
    }
}

fn identity(
    owner: &policy::request_contract::RequestContracts,
    inventory: &Inventory,
    index: usize,
    comparison: &Comparison,
) -> Result<IdentityDecision> {
    let scope = inventory.scope(index);
    if inventory.core.exchanges[index].source.source == ReplaySource::Case {
        owner.preview_identity_pairs(&scope, &comparison.identity_pairs())
    } else {
        owner.preview_run_identity_pairs(&scope, &comparison.identity_pairs())
    }
}

impl<P: ReplayProtocolSet> admission::request::DependencyRequestAdapter<RuntimeState<P>>
    for Request
{
    type Matched = Matched;
    type Error = Rejected;
    fn sequence_request_bytes(&self) -> Option<usize> {
        Some(self.bytes)
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
            });
        }
        let native = &state.native;
        let selected = native.core.select(
            MatchContext {
                protocol: self.protocol,
                endpoint: &self.endpoint,
                active_case: observation.case.as_deref(),
                request: self.message.as_ref(),
                metadata: &crate::value_contract::json::PolicyMetadata,
            },
            |exchange| native.clocks(exchange.index, self.observed, false),
            |exchange, comparison| {
                identity(&native.contracts, native, exchange.index, comparison).map(|_| ())
            },
        )?;
        let selected = match selected {
            Selection::Matched(selected) => selected,
            Selection::LaneBlocked { blocker, .. } => {
                return Err(Rejected {
                    reason: "recorded native connection predecessor has not reached its required barrier"
                        .into(),
                    blocker: Some(blocker),
                });
            }
            Selection::NotFound => {
                return Err(Rejected {
                    reason: "no recorded native request matched the active Source scope".into(),
                    blocker: None,
                });
            }
        };
        let index = selected.index;
        let request_identity = identity(&native.contracts, native, index, &selected.comparison)?;
        let delay = native.core.exchanges[index].native.response_delay;
        let run_owned = native.core.exchanges[index].source.source.is_run_owned();
        let mut decision =
            policy::request_contract::Decision::from_value_comparison(selected.comparison);
        decision.identity = Some(request_identity);
        let ticket = state.native.core.claim(index)?;
        if let Err(error) = state.native.contracts.commit(decision) {
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
        }
    }

    fn on_rejected(
        &mut self,
        state: &mut RuntimeState<P>,
        observation: &admission::RequestAdmission,
        error: &Rejected,
    ) {
        state.native.record_failure(
            self.protocol,
            &self.endpoint,
            observation.case.clone(),
            observation.event_index,
            observation.observation_id,
            &error.reason,
        );
    }
}

impl Inventory {
    pub(super) fn render_response(
        &self,
        index: usize,
        observed: DateTime<Utc>,
    ) -> Result<Box<dyn traffic_protocol::output::OutputStream>> {
        let exchange = &self.core.exchanges[index];
        let scope = self.scope(index);
        let rendered = exchange.response.render_delivery(
            self.clocks(index, observed, true),
            &crate::value_contract::json::PolicyMetadata,
            &exchange.rebase_time,
            |selected| {
                self.contracts
                    .identity_deliveries(&scope, selected)
                    .map(|(values, _)| values)
            },
        )?;
        let proposed = identity(&self.contracts, self, index, &rendered.comparison)?;
        let response = exchange.native.response.output(&rendered.values)?;
        let mut decision =
            policy::request_contract::Decision::from_value_comparison(rendered.comparison);
        decision.identity = Some(proposed);
        self.contracts.commit(decision)?;
        Ok(response)
    }
}
