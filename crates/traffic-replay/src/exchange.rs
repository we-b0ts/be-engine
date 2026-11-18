//! Shared finite inventory for protocol-projected dependency exchanges.
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use traffic_model::recording::{CaptureMetadata, ProtocolRef};
use traffic_protocol::{
    ProtocolId,
    connection::{Endpoint, RecordedExchange},
    message::ProtocolMessage,
};
use uuid::Uuid;

mod sessions;
pub use sessions::SessionBindings;

use crate::{
    Barrier, ClaimKind, ClaimTicket, Finish, Lifecycle, ReplayExchangeStatus, ReplaySource,
    command::{CommandExchangeScope, PreferredMatch, preferred_match_indexed_with_priority},
    index::{
        CandidateCursor, CandidateIndex, CaseMembership, LaneIndex, LaneKey, LaneOwner,
        ScopePartition,
    },
    rules::{ExactRules, RuleRuntime},
};

#[derive(Debug, Clone)]
pub struct SourceContext {
    pub source: ReplaySource,
    pub case_id: Option<String>,
    pub position: u64,
    pub capture: Option<CaptureMetadata>,
}

pub struct ExchangeRules<R: RuleRuntime = ExactRules> {
    pub request: R::Bindings,
    pub response: R::Bindings,
    pub delivery: R::Delivery,
}

pub struct PreparedExchange<R: RuleRuntime = ExactRules> {
    pub index: usize,
    pub protocol: ProtocolId,
    pub native: RecordedExchange,
    pub source: SourceContext,
    pub request: Option<R::Prepared>,
    pub response: R::Prepared,
    pub delivery: R::Delivery,
    pub status: ReplayExchangeStatus,
    lane_id: Uuid,
}

impl<R: RuleRuntime> std::fmt::Debug for PreparedExchange<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedExchange")
            .field("protocol", &self.protocol)
            .field("index", &self.index)
            .field("status", &self.status)
            .finish()
    }
}

impl<R: RuleRuntime> CommandExchangeScope for PreparedExchange<R> {
    fn source(&self) -> ReplaySource {
        self.source.source
    }
    fn case_id(&self) -> Option<&str> {
        self.source.case_id.as_deref()
    }
    fn connection_id(&self) -> Uuid {
        self.lane_id
    }
    fn sequence(&self) -> u64 {
        self.source.position
    }
    fn command(&self) -> &str {
        ""
    }
    fn is_available(&self) -> bool {
        self.status.is_available()
    }
    fn is_consumed(&self) -> bool {
        self.status.is_consumed()
    }
    fn preserves_connection_order(&self) -> bool {
        self.native.lane.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CandidateKey {
    scope: ScopePartition,
    protocol: ProtocolId,
    endpoint: Endpoint,
    structure: Vec<u8>,
}

type LaneIdentity = (ScopePartition, ProtocolId, Endpoint, String);

pub struct ExchangeInventory<R: RuleRuntime = ExactRules> {
    pub exchanges: Vec<PreparedExchange<R>>,
    pub lifecycle: Lifecycle,
    pub sessions: SessionBindings,
    candidates: CandidateIndex<CandidateKey>,
    lanes: LaneIndex,
    lane_ids: HashMap<LaneIdentity, Uuid>,
    cases: CaseMembership,
    references: BTreeMap<String, BTreeMap<ProtocolRef, Option<usize>>>,
    emissions: BTreeMap<ProtocolRef, Vec<usize>>,
}

impl<R: RuleRuntime> Default for ExchangeRules<R> {
    fn default() -> Self {
        Self {
            request: Default::default(),
            response: Default::default(),
            delivery: Default::default(),
        }
    }
}
impl<R: RuleRuntime> Default for ExchangeInventory<R> {
    fn default() -> Self {
        Self {
            exchanges: Default::default(),
            lifecycle: Default::default(),
            sessions: Default::default(),
            candidates: Default::default(),
            lanes: Default::default(),
            lane_ids: Default::default(),
            cases: Default::default(),
            references: Default::default(),
            emissions: Default::default(),
        }
    }
}
impl<R: RuleRuntime> std::fmt::Debug for ExchangeInventory<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExchangeInventory")
            .field("exchanges", &self.exchanges.len())
            .finish()
    }
}

pub struct SelectedExchange<C = bool> {
    pub index: usize,
    pub comparison: C,
}

pub enum Selection<C = bool> {
    Matched(Box<SelectedExchange<C>>),
    LaneBlocked { candidate: usize, blocker: usize },
    NotFound,
}

pub struct MatchContext<'a, R: RuleRuntime = ExactRules> {
    pub protocol: ProtocolId,
    pub endpoint: &'a Endpoint,
    pub active_case: Option<&'a str>,
    pub request: &'a dyn ProtocolMessage,
    pub session: Option<Uuid>,
    pub lane: Option<&'a str>,
    pub metadata: &'a R::Metadata,
}

impl<R: RuleRuntime> ExchangeInventory<R> {
    pub fn register(
        &mut self,
        protocol: ProtocolId,
        native: RecordedExchange,
        source: SourceContext,
        rules: ExchangeRules<R>,
    ) -> Result<usize> {
        ensure!(
            native.reference.protocol() == protocol.as_str(),
            "native reference protocol changed"
        );
        ensure!(
            source.source != ReplaySource::Case || source.case_id.is_some(),
            "Case exchange has no owner"
        );
        let index = self.exchanges.len();
        let request = native
            .request()
            .map(|request| R::prepare(request, &rules.request))
            .transpose()?;
        let response = R::prepare(native.response.as_ref(), &rules.response)?;
        let scope = ScopePartition::new(source.source, source.case_id.as_deref());
        let lane_id = native
            .lane
            .as_ref()
            .map(|lane| {
                *self
                    .lane_ids
                    .entry((
                        scope.clone(),
                        protocol,
                        native.endpoint.clone(),
                        lane.clone(),
                    ))
                    .or_insert_with(Uuid::new_v4)
            })
            .unwrap_or_else(Uuid::new_v4);
        let key = CandidateKey {
            scope,
            protocol,
            endpoint: native.endpoint.clone(),
            structure: request
                .as_ref()
                .map(|request| serde_json::to_vec(R::structure(request)))
                .transpose()?
                .unwrap_or_default(),
        };
        if native.lane.is_some() && request.is_some() {
            self.lanes.register(
                LaneKey {
                    owner: LaneOwner::new(source.source),
                    case: source.case_id.clone(),
                    connection: lane_id,
                },
                source.position,
                index,
            );
        }
        if request.is_some() {
            self.candidates.register(key, index);
        }
        self.cases
            .register(source.source, source.case_id.as_deref(), index);
        if source.source == ReplaySource::Case {
            let case = source.case_id.as_ref().expect("Case owner validated");
            self.references
                .entry(case.clone())
                .or_default()
                .entry(native.reference.clone())
                .and_modify(|slot| *slot = None)
                .or_insert(Some(index));
        }
        if let traffic_protocol::connection::RecordedInput::Emission { after, .. } = &native.input {
            ensure!(
                after.protocol() == protocol.as_str(),
                "native emission anchor changed protocol"
            );
            self.emissions.entry(after.clone()).or_default().push(index);
        }
        self.exchanges.push(PreparedExchange {
            index,
            protocol,
            native,
            source,
            request,
            response,
            delivery: rules.delivery,
            status: ReplayExchangeStatus::Available,
            lane_id,
        });
        Ok(index)
    }

    pub fn seal(&mut self) {
        self.candidates.seal();
        self.cases.seal();
    }

    pub fn case_members(&self, case: &str) -> Arc<[usize]> {
        self.cases.for_case(case)
    }

    pub fn resolve_reference(&self, case: &str, reference: &ProtocolRef) -> Result<Option<usize>> {
        let Some(index) = self
            .references
            .get(case)
            .and_then(|references| references.get(reference))
        else {
            return Ok(None);
        };
        index
            .map(Some)
            .context("native semantic reference is ambiguous in its Case inventory")
    }

    fn candidates(&self, key: CandidateKey, source: ReplaySource) -> CandidateCursor {
        if let Some(expected) = self.lifecycle.sequence.expected_in(source) {
            let selected = self.candidates.lookup(&key).into_indices();
            CandidateCursor::new(
                expected
                    .iter()
                    .copied()
                    .filter(|index| selected.binary_search(index).is_ok())
                    .collect::<Vec<_>>()
                    .into(),
            )
        } else {
            self.candidates.lookup(&key)
        }
    }

    pub fn select(
        &self,
        context: MatchContext<'_, R>,
        clocks: impl Fn(&PreparedExchange<R>) -> R::Context,
        validate: impl Fn(&PreparedExchange<R>, &R::Comparison) -> Result<()>,
    ) -> Result<Selection<R::Comparison>> {
        self.select_observed(context, clocks, validate, |_, _| Ok(()))
    }

    pub fn select_observed(
        &self,
        context: MatchContext<'_, R>,
        clocks: impl Fn(&PreparedExchange<R>) -> R::Context,
        validate: impl Fn(&PreparedExchange<R>, &R::Comparison) -> Result<()>,
        observe: impl Fn(&PreparedExchange<R>, &R::Comparison) -> Result<()>,
    ) -> Result<Selection<R::Comparison>> {
        let structure = serde_json::to_vec(&context.request.project()?.structure)?;
        let key = CandidateKey {
            scope: ScopePartition::new(ReplaySource::Case, context.active_case),
            protocol: context.protocol,
            endpoint: context.endpoint.clone(),
            structure,
        };
        let case = self.candidates(key.clone(), ReplaySource::Case);
        let run = self.candidates(
            CandidateKey {
                scope: ScopePartition::Run,
                ..key
            },
            ReplaySource::Startup,
        );
        let previews = RefCell::new(HashMap::new());
        let failed = RefCell::new(None);
        let inspected = std::cell::Cell::new(0_usize);
        let selected = preferred_match_indexed_with_priority(
            &self.exchanges,
            context.active_case,
            case,
            run,
            |exchange, _| {
                if !self
                    .lifecycle
                    .live_status(exchange.index, exchange.status)
                    .is_available()
                {
                    return false;
                }
                if context
                    .lane
                    .is_some_and(|lane| exchange.native.lane.as_deref() != Some(lane))
                    || !self.sessions.accepts(
                        exchange.protocol,
                        &exchange.native.endpoint,
                        exchange.native.lane.as_deref(),
                        context.session,
                    )
                {
                    return false;
                }
                inspected.set(inspected.get() + 1);
                if inspected.get() > 16_384 {
                    *failed.borrow_mut() = Some(anyhow::anyhow!(
                        "native candidate comparison budget exceeded"
                    ));
                    return false;
                }
                match R::compare(
                    exchange.request.as_ref().expect("request candidate"),
                    context.request,
                    clocks(exchange),
                    context.metadata,
                ) {
                    Ok(comparison) => {
                        if let Err(error) = observe(exchange, &comparison) {
                            *failed.borrow_mut() = Some(error);
                            return false;
                        }
                        if R::passed(&comparison) && validate(exchange, &comparison).is_ok() {
                            previews.borrow_mut().insert(exchange.index, comparison);
                            true
                        } else {
                            false
                        }
                    }
                    Err(error) => {
                        *failed.borrow_mut() = Some(error);
                        false
                    }
                }
            },
            |_| true,
            |index| {
                self.lanes.blocker(index, |prior| {
                    let exchange = &self.exchanges[prior];
                    !Lifecycle::satisfies(
                        self.lifecycle.live_status(prior, exchange.status),
                        exchange.source.source,
                        Barrier::Admitted,
                    )
                })
            },
        );
        if let Some(error) = failed.into_inner() {
            return Err(error);
        }
        Ok(match selected {
            PreferredMatch::Matched(index) => Selection::Matched(Box::new(SelectedExchange {
                index,
                comparison: previews
                    .into_inner()
                    .remove(&index)
                    .context("selected native comparison absent")?,
            })),
            PreferredMatch::LaneBlocked { candidate, blocker } => {
                Selection::LaneBlocked { candidate, blocker }
            }
            PreferredMatch::NotFound => Selection::NotFound,
        })
    }

    /// Only provider-selected, actually delivered anchors may enter this path.
    /// Emissions never participate in Target request candidate selection.
    pub fn has_messages_after(&self, reference: &ProtocolRef) -> bool {
        self.emissions.contains_key(reference)
    }

    pub fn select_message(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        active_case: Option<&str>,
        anchors: &[ProtocolRef],
    ) -> Option<usize> {
        let case_expected = self
            .lifecycle
            .sequence
            .expected_messages(ReplaySource::Case);
        let run_expected = self
            .lifecycle
            .sequence
            .expected_messages(ReplaySource::Startup);
        anchors
            .iter()
            .flat_map(|anchor| self.emissions.get(anchor).into_iter().flatten())
            .copied()
            .filter(|index| {
                let exchange = &self.exchanges[*index];
                let scope = &exchange.source;
                if exchange.protocol != protocol
                    || exchange.native.endpoint != *endpoint
                    || !self
                        .lifecycle
                        .live_status(*index, exchange.status)
                        .is_available()
                {
                    return false;
                }
                if scope.source == ReplaySource::Case {
                    scope.case_id.as_deref() == active_case
                        && case_expected
                            .as_ref()
                            .is_none_or(|expected| expected.contains(index))
                } else {
                    scope.source.is_run_owned()
                        && run_expected
                            .as_ref()
                            .is_none_or(|expected| expected.contains(index))
                }
            })
            .min_by_key(|index| {
                let source = &self.exchanges[*index].source;
                (source.source != ReplaySource::Case, source.position)
            })
    }

    pub fn claim_bound(&mut self, index: usize, owner: Uuid) -> Result<ClaimTicket> {
        let exchange = &self.exchanges[index];
        let lane = exchange
            .native
            .lane
            .as_deref()
            .context("stateful native Source has no session lane")?;
        self.sessions
            .bind(exchange.protocol, &exchange.native.endpoint, lane, owner)?;
        self.claim(index)
    }

    pub fn claim(&mut self, index: usize) -> Result<ClaimTicket> {
        let exchange = self
            .exchanges
            .get_mut(index)
            .context("native exchange position absent")?;
        self.lifecycle
            .claim(index, &mut exchange.status, ClaimKind::Response)
            .context("native exchange cannot be claimed")
    }

    pub fn finish<T>(
        &mut self,
        index: usize,
        ticket: &ClaimTicket,
        commit: impl FnOnce() -> Result<T>,
    ) -> Finish<T> {
        self.lifecycle
            .finish(ticket, &mut self.exchanges[index].status, commit)
    }

    pub fn fail(&mut self, index: usize, ticket: &ClaimTicket) {
        self.lifecycle
            .fail(ticket, &mut self.exchanges[index].status);
    }
}

#[cfg(test)]
mod tests;
