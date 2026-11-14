//! Shared finite inventory for protocol-projected dependency exchanges.
use std::{cell::RefCell, collections::HashMap, sync::Arc};

use anyhow::{Context, Result, ensure};
use traffic_contract::compare::{AnchorClocks, Comparison, RuleMetadata};
use traffic_model::recording::CaptureMetadata;
use traffic_protocol::{
    ProtocolId,
    connection::{Endpoint, RecordedExchange},
    message::ProtocolMessage,
};
use uuid::Uuid;

use crate::{
    Barrier, ClaimKind, ClaimTicket, Finish, Lifecycle, ReplayExchangeStatus, ReplaySource,
    command::{CommandExchangeScope, PreferredMatch, preferred_match_indexed_with_priority},
    index::{
        CandidateCursor, CandidateIndex, CaseMembership, LaneIndex, LaneKey, LaneOwner,
        ScopePartition,
    },
    rules::{PreparedMessage, RuleBinding},
};

#[derive(Debug, Clone)]
pub struct SourceContext {
    pub source: ReplaySource,
    pub case_id: Option<String>,
    pub position: u64,
    pub capture: Option<CaptureMetadata>,
}

#[derive(Default)]
pub struct ExchangeRules {
    pub request: Vec<RuleBinding>,
    pub response: Vec<RuleBinding>,
    pub rebase_time: std::collections::BTreeSet<String>,
}

pub struct PreparedExchange {
    pub index: usize,
    pub protocol: ProtocolId,
    pub native: RecordedExchange,
    pub source: SourceContext,
    pub request: PreparedMessage,
    pub response: PreparedMessage,
    pub rebase_time: std::collections::BTreeSet<String>,
    pub status: ReplayExchangeStatus,
    lane_id: Uuid,
}

impl std::fmt::Debug for PreparedExchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedExchange")
            .field("protocol", &self.protocol)
            .field("index", &self.index)
            .field("status", &self.status)
            .finish()
    }
}

impl CommandExchangeScope for PreparedExchange {
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

#[derive(Debug, Default)]
pub struct ExchangeInventory {
    pub exchanges: Vec<PreparedExchange>,
    pub lifecycle: Lifecycle,
    candidates: CandidateIndex<CandidateKey>,
    lanes: LaneIndex,
    lane_ids: HashMap<LaneIdentity, Uuid>,
    cases: CaseMembership,
}

pub struct SelectedExchange {
    pub index: usize,
    pub comparison: Comparison,
}

pub enum Selection {
    Matched(Box<SelectedExchange>),
    LaneBlocked { candidate: usize, blocker: usize },
    NotFound,
}

pub struct MatchContext<'a> {
    pub protocol: ProtocolId,
    pub endpoint: &'a Endpoint,
    pub active_case: Option<&'a str>,
    pub request: &'a dyn ProtocolMessage,
    pub metadata: &'a dyn RuleMetadata,
}

impl ExchangeInventory {
    pub fn register(
        &mut self,
        protocol: ProtocolId,
        native: RecordedExchange,
        source: SourceContext,
        rules: ExchangeRules,
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
        let request = PreparedMessage::compile(native.request.as_ref(), &rules.request)?;
        let response = PreparedMessage::compile(native.response.as_ref(), &rules.response)?;
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
            structure: serde_json::to_vec(request.structure())?,
        };
        if native.lane.is_some() {
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
        self.candidates.register(key, index);
        self.cases
            .register(source.source, source.case_id.as_deref(), index);
        self.exchanges.push(PreparedExchange {
            index,
            protocol,
            native,
            source,
            request,
            response,
            rebase_time: rules.rebase_time,
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
        context: MatchContext<'_>,
        clocks: impl Fn(&PreparedExchange) -> AnchorClocks,
        validate: impl Fn(&PreparedExchange, &Comparison) -> Result<()>,
    ) -> Result<Selection> {
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
                inspected.set(inspected.get() + 1);
                if inspected.get() > 16_384 {
                    *failed.borrow_mut() = Some(anyhow::anyhow!(
                        "native candidate comparison budget exceeded"
                    ));
                    return false;
                }
                match exchange
                    .request
                    .compare(context.request, clocks(exchange), context.metadata)
                {
                    Ok(comparison)
                        if comparison.passed() && validate(exchange, &comparison).is_ok() =>
                    {
                        previews.borrow_mut().insert(exchange.index, comparison);
                        true
                    }
                    Ok(_) => false,
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
