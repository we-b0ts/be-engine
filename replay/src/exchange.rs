//! Shared finite inventory for protocol-projected dependency exchanges.
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_model::recording::{CaptureMetadata, ProtocolRef};
use traffic_protocol::{
    ProtocolId,
    connection::{Endpoint, RecordedExchange, ReplaySessionStep, RequestSession},
    message::{MessageEncoder, ProjectedMessage, ProtocolMessage},
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
    pub response: Option<R::Prepared>,
    pub delivery: R::Delivery,
    pub status: ReplayExchangeStatus,
    pub session_step: Option<ReplaySessionStep>,
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
    transaction_starts: BTreeSet<usize>,
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
            transaction_starts: Default::default(),
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
    SessionUnverified,
    NotFound,
}

pub struct MatchContext<'a, R: RuleRuntime = ExactRules> {
    pub protocol: ProtocolId,
    pub endpoint: &'a Endpoint,
    pub active_case: Option<&'a str>,
    pub request: &'a dyn ProtocolMessage,
    pub session: Option<Uuid>,
    pub lane: Option<&'a str>,
    pub request_session: Option<&'a RequestSession>,
    pub metadata: &'a R::Metadata,
}

struct RequestForm<'a> {
    message: &'a dyn ProtocolMessage,
    projection: ProjectedMessage,
}

impl<'a> RequestForm<'a> {
    fn new(message: &'a dyn ProtocolMessage) -> Result<Self> {
        Ok(Self {
            message,
            projection: message.project()?,
        })
    }
}

struct RequestForms<'a> {
    primary: RequestForm<'a>,
    read_only_end_alternative: Option<RequestForm<'a>>,
    exact_alternative: Option<RequestForm<'a>>,
}

impl<'a> RequestForms<'a> {
    fn new(request: &'a dyn ProtocolMessage, session: Option<&'a RequestSession>) -> Result<Self> {
        Ok(Self {
            primary: RequestForm::new(request)?,
            read_only_end_alternative: session
                .and_then(|session| session.read_only_end_alternative.as_deref())
                .map(RequestForm::new)
                .transpose()?,
            exact_alternative: request
                .exact_request_alternative()
                .map(RequestForm::new)
                .transpose()?,
        })
    }

    fn matching<R: RuleRuntime>(
        &self,
        prepared: &R::Prepared,
        exchange: &PreparedExchange<R>,
    ) -> Result<Option<&'a dyn ProtocolMessage>> {
        let structure = R::structure(prepared);
        if self.primary.projection.structure == *structure {
            return Ok(Some(self.primary.message));
        }
        if let Some(form) = &self.read_only_end_alternative
            && matches!(
                exchange.session_step,
                Some(ReplaySessionStep::ReadOnlyEnd { .. })
            )
            && form.projection.structure == *structure
        {
            return Ok(Some(form.message));
        }
        if let Some(form) = &self.exact_alternative
            && form.projection.structure == *structure
        {
            let source = exchange
                .native
                .request()
                .context("alternate request has no Source request")?
                .project()?;
            if source.structure == form.projection.structure
                && source.values.len() == form.projection.values.len()
                && source.values.iter().all(|(path, value)| {
                    form.projection.values.get(path).is_some_and(|actual| {
                        actual.scalar_encoding == value.scalar_encoding
                            && actual.bytes == value.bytes
                    })
                })
            {
                return Ok(Some(form.message));
            }
        }
        Ok(None)
    }
}

fn compare_request<R: RuleRuntime>(
    exchange: &PreparedExchange<R>,
    prepared: &R::Prepared,
    actual: &dyn ProtocolMessage,
    context: &MatchContext<'_, R>,
    clocks: &impl Fn(&PreparedExchange<R>) -> R::Context,
    session_trace: bool,
) -> Result<R::Comparison> {
    let comparison = R::compare(prepared, actual, clocks(exchange), context.metadata)?;
    if session_trace
        && !R::passed(&comparison)
        && let Some(source) = exchange.native.request()
        && actual.exact_request_reordering_of(source)
    {
        // The protocol proved that reordering the Target's unchanged values
        // reconstructs the Source view. Keep physical value-rule locations.
        return R::compare(prepared, source, clocks(exchange), context.metadata);
    }
    Ok(comparison)
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
        let response = native
            .response
            .stored()
            .is_none()
            .then(|| R::prepare(native.response.as_ref(), &rules.response))
            .transpose()?;
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
            session_step: None,
            lane_id,
        });
        Ok(index)
    }

    pub fn seal(&mut self) {
        self.candidates.seal();
        self.cases.seal();
    }

    pub fn set_session_step(&mut self, index: usize, step: Option<ReplaySessionStep>) {
        if matches!(
            step,
            Some(ReplaySessionStep::Start | ReplaySessionStep::ImplicitStart)
        ) {
            self.transaction_starts.insert(index);
        } else {
            self.transaction_starts.remove(&index);
        }
        self.exchanges[index].session_step = step;
    }

    pub fn can_defer_transaction_start(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        request: &dyn ProtocolMessage,
        head: crate::SourceEvent,
    ) -> bool {
        self.transaction_starts
            .iter()
            .filter_map(|&index| {
                let exchange = &self.exchanges[index];
                let capture = exchange.source.capture.as_ref()?;
                (capture.semantic_required
                    && capture.sequence >= head.sequence
                    && exchange.source.source.is_run_owned()
                    && exchange.protocol == protocol
                    && exchange.native.endpoint == *endpoint
                    && self
                        .lifecycle
                        .live_status(index, exchange.status)
                        .is_available()
                    && exchange
                        .native
                        .request()
                        .is_some_and(|recorded| request.same_session_identity(recorded)))
                .then_some((capture.sequence, exchange.session_step.as_ref()))
            })
            .min_by_key(|(sequence, _)| *sequence)
            .is_some_and(|(_, step)| step == Some(&ReplaySessionStep::ImplicitStart))
    }

    fn request_candidates(
        &self,
        context: &MatchContext<'_, R>,
        scope: ScopePartition,
        forms: &RequestForms<'_>,
    ) -> Result<CandidateCursor> {
        let lookup = |structure: &Value| -> Result<CandidateCursor> {
            Ok(self.candidates.lookup(&CandidateKey {
                scope: scope.clone(),
                protocol: context.protocol,
                endpoint: context.endpoint.clone(),
                structure: serde_json::to_vec(structure)?,
            }))
        };
        let primary = lookup(&forms.primary.projection.structure)?;
        let read_only = forms
            .read_only_end_alternative
            .as_ref()
            .map(|form| lookup(&form.projection.structure))
            .transpose()?;
        let exact = forms
            .exact_alternative
            .as_ref()
            .map(|form| lookup(&form.projection.structure))
            .transpose()?;
        match (read_only, exact) {
            (Some(read_only), Some(exact)) => Ok(primary.merge(read_only.merge(exact))),
            (Some(alternate), None) | (None, Some(alternate)) => Ok(primary.merge(alternate)),
            (None, None) => Ok(primary),
        }
    }

    pub fn statement_metadata(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        template: &dyn ProtocolMessage,
        session: &RequestSession,
        head: crate::SourceEvent,
    ) -> Option<Arc<dyn MessageEncoder>> {
        let matches = |exchange: &PreparedExchange<R>| {
            exchange
                .native
                .request()
                .is_some_and(|source| template.matches_statement_template(source))
        };
        let expected = self
            .expected_request(protocol, endpoint, None, session)
            .filter(|exchange| matches(exchange));
        let future = || {
            self.exchanges
                .iter()
                .filter_map(|exchange| {
                    let capture = exchange.source.capture.as_ref()?;
                    (capture.semantic_required
                        && capture.sequence >= head.sequence
                        && exchange.source.source.is_run_owned()
                        && exchange.protocol == protocol
                        && exchange.native.endpoint == *endpoint
                        && self
                            .lifecycle
                            .live_status(exchange.index, exchange.status)
                            .is_available()
                        && self.sessions.accepts(
                            protocol,
                            endpoint,
                            exchange.native.lane.as_deref(),
                            None,
                        )
                        && accepts_session(exchange.session_step.as_ref(), Some(session))
                        && matches(exchange))
                    .then_some((capture.sequence, exchange))
                })
                .min_by_key(|(sequence, _)| *sequence)
                .map(|(_, exchange)| exchange)
        };
        expected
            .or_else(future)
            .map(|exchange| exchange.native.response.clone())
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

    /// Inspect the unique eligible Source request at the live sequence heads.
    /// Rejected commands never claim or advance an exchange.
    pub fn expected_request(
        &self,
        protocol: ProtocolId,
        endpoint: &Endpoint,
        active_case: Option<&str>,
        session: &RequestSession,
    ) -> Option<&PreparedExchange<R>> {
        let expected = [
            self.lifecycle.sequence.expected_in(ReplaySource::Case),
            self.lifecycle.sequence.expected_in(ReplaySource::Startup),
        ];
        let mut eligible = expected
            .iter()
            .flatten()
            .flat_map(|indices| indices.iter())
            .map(|&index| &self.exchanges[index])
            .filter(|exchange| {
                let source = &exchange.source;
                (source.source.is_run_owned()
                    || source.source == ReplaySource::Case
                        && source.case_id.as_deref() == active_case)
                    && exchange.protocol == protocol
                    && &exchange.native.endpoint == endpoint
                    && self
                        .lifecycle
                        .live_status(exchange.index, exchange.status)
                        .is_available()
                    && self.sessions.accepts(
                        protocol,
                        endpoint,
                        exchange.native.lane.as_deref(),
                        None,
                    )
                    && accepts_session(exchange.session_step.as_ref(), Some(session))
                    && self.lane_blocker(exchange.index).is_none()
            });
        let exchange = eligible.next()?;
        eligible.next().is_none().then_some(exchange)
    }

    fn lane_blocker(&self, index: usize) -> Option<usize> {
        let session = self.lifecycle.sequence.is_session_trace();
        self.lanes.blocker(index, |prior| {
            let exchange = &self.exchanges[prior];
            let status = self.lifecycle.live_status(prior, exchange.status);
            // A whole-session trace records the actual admission and output
            // barriers even when Source storage uses the run-owned scope.
            !(session && status == ReplayExchangeStatus::Responding
                || Lifecycle::satisfies(status, exchange.source.source, Barrier::Admitted))
        })
    }

    /// An early observation can wait only while a later compatible request
    /// remains possible. This preview does not bind lanes or commit value rules.
    pub fn may_follow_session_head(
        &self,
        context: &MatchContext<'_, R>,
        head: crate::SourceEvent,
        clocks: impl Fn(&PreparedExchange<R>) -> R::Context,
    ) -> Result<bool> {
        const PREVIEW_LIMIT: usize = 256;
        let include_head = head.kind == crate::EventKind::Request
            && self
                .lifecycle
                .sequence
                .expected_in(ReplaySource::Startup)
                .is_some_and(|expected| expected.is_empty());
        let session_trace = self.lifecycle.sequence.is_session_trace();
        let forms = RequestForms::new(context.request, context.request_session)?;
        let candidates = self.request_candidates(context, ScopePartition::Run, &forms)?;
        for (position, index) in candidates.enumerate() {
            if position == PREVIEW_LIMIT {
                return Ok(true);
            }
            let exchange = &self.exchanges[index];
            let Some(prepared) = exchange.request.as_ref() else {
                continue;
            };
            let Some(request) = forms.matching(prepared, exchange)? else {
                continue;
            };
            let Some(capture) = &exchange.source.capture else {
                continue;
            };
            let lane = exchange.native.lane.as_deref();
            if capture.semantic_required
                && (capture.sequence > head.sequence
                    || include_head && capture.sequence == head.sequence)
                && self
                    .lifecycle
                    .live_status(index, exchange.status)
                    .is_available()
                && context.lane.is_none_or(|current| Some(current) == lane)
                && self.sessions.accepts(
                    exchange.protocol,
                    &exchange.native.endpoint,
                    lane,
                    context.session,
                )
                && accepts_session(exchange.session_step.as_ref(), context.request_session)
                && R::passed(&compare_request(
                    exchange,
                    prepared,
                    request,
                    context,
                    &clocks,
                    session_trace,
                )?)
            {
                return Ok(true);
            }
        }
        Ok(false)
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
        let case = self.lifecycle.sequence.expected_in(ReplaySource::Case);
        let run = self.lifecycle.sequence.expected_in(ReplaySource::Startup);
        let session_trace = self.lifecycle.sequence.is_session_trace();
        let forms = RequestForms::new(context.request, context.request_session)?;
        let case = match case {
            Some(expected) => CandidateCursor::new(expected),
            None => self.request_candidates(
                &context,
                ScopePartition::new(ReplaySource::Case, context.active_case),
                &forms,
            )?,
        };
        let run = match run {
            Some(expected) => CandidateCursor::new(expected),
            None => self.request_candidates(&context, ScopePartition::Run, &forms)?,
        };
        let previews = RefCell::new(HashMap::new());
        let failed = RefCell::new(None);
        let inspected = std::cell::Cell::new(0_usize);
        let unverified = std::cell::Cell::new(false);
        let selected = preferred_match_indexed_with_priority(
            &self.exchanges,
            context.active_case,
            case,
            run,
            |exchange, _| {
                let Some(prepared) = exchange.request.as_ref() else {
                    return false;
                };
                if exchange.protocol != context.protocol
                    || exchange.native.endpoint != *context.endpoint
                    || !self
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
                let session_matches =
                    accepts_session(exchange.session_step.as_ref(), context.request_session);
                let session_unverified =
                    exchange.session_step == Some(ReplaySessionStep::Unverified);
                if !session_matches && !session_unverified {
                    return false;
                }
                let request = match forms.matching(prepared, exchange) {
                    Ok(Some(request)) => request,
                    Ok(None) => return false,
                    Err(error) => {
                        *failed.borrow_mut() = Some(error);
                        return false;
                    }
                };
                inspected.set(inspected.get() + 1);
                if inspected.get() > 16_384 {
                    *failed.borrow_mut() = Some(anyhow::anyhow!(
                        "native candidate comparison budget exceeded"
                    ));
                    return false;
                }
                match compare_request(
                    exchange,
                    prepared,
                    request,
                    &context,
                    &clocks,
                    session_trace,
                ) {
                    Ok(comparison) => {
                        if let Err(error) = observe(exchange, &comparison) {
                            *failed.borrow_mut() = Some(error);
                            return false;
                        }
                        if R::passed(&comparison) && validate(exchange, &comparison).is_ok() {
                            if session_unverified {
                                unverified.set(true);
                                return false;
                            }
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
            |index| self.lane_blocker(index),
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
            PreferredMatch::NotFound if unverified.get() => Selection::SessionUnverified,
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
        let select_scope = |source| {
            let matches = |index: &usize| {
                let exchange = &self.exchanges[*index];
                let scope = &exchange.source;
                let owned = if source == ReplaySource::Case {
                    scope.source == ReplaySource::Case && scope.case_id.as_deref() == active_case
                } else {
                    scope.source.is_run_owned()
                };
                owned
                    && exchange.protocol == protocol
                    && exchange.native.endpoint == *endpoint
                    && self
                        .lifecycle
                        .live_status(*index, exchange.status)
                        .is_available()
                    && matches!(&exchange.native.input,
                        traffic_protocol::connection::RecordedInput::Emission { after, .. }
                        if anchors.contains(after))
            };
            let position = |index: &usize| self.exchanges[*index].source.position;
            if let Some(expected) = self.lifecycle.sequence.expected_messages(source) {
                expected.into_iter().filter(matches).min_by_key(position)
            } else {
                anchors
                    .iter()
                    .flat_map(|anchor| self.emissions.get(anchor).into_iter().flatten())
                    .copied()
                    .filter(matches)
                    .min_by_key(position)
            }
        };
        if !self.lifecycle.sequence.is_session_trace()
            && let Some(index) = select_scope(ReplaySource::Case)
        {
            return Some(index);
        }
        select_scope(ReplaySource::Startup)
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

fn accepts_session(step: Option<&ReplaySessionStep>, session: Option<&RequestSession>) -> bool {
    let after = session.and_then(|session| session.after.as_ref());
    if session.is_some_and(|session| session.implicit_start_pending) {
        return step == Some(&ReplaySessionStep::ImplicitStart)
            && after.is_none()
            && session.is_some_and(|session| session.can_start);
    }
    match step {
        None => after.is_none(),
        Some(ReplaySessionStep::Optional | ReplaySessionStep::Unverified) => false,
        Some(
            ReplaySessionStep::Start
            | ReplaySessionStep::ImplicitStart
            | ReplaySessionStep::InTransaction,
        ) => after.is_none() && session.is_some_and(|session| session.can_start),
        Some(
            ReplaySessionStep::Continue {
                after: expected, ..
            }
            | ReplaySessionStep::ReadOnlyEnd { after: expected },
        ) => after == Some(expected),
    }
}

#[cfg(test)]
mod tests;
