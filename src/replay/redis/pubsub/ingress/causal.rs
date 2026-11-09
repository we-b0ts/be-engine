//! Source request prefixes and actual native events admit remote input causally.
use super::*;
use crate::interaction::replay::NativeEvent;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) struct Prerequisite {
    wire: Wire,
    exchange_index: usize,
    event: String,
    occurrence: u64,
}

#[derive(Debug)]
pub(super) struct LiveEvents {
    case: String,
    epoch: DateTime<Utc>,
    ordinals: HashMap<String, u64>,
    counts: HashMap<(String, String), u64>,
}

impl super::super::super::RedisReplayState {
    pub(in crate::replay) fn native_request_epoch(&self, case: &str) -> Option<DateTime<Utc>> {
        // Derived input admission can re-anchor request policy time to the
        // signed send time. The native feedback and Redis delivery still
        // belong to the session opened by request_begin.
        self.pubsub
            .native_clock
            .epoch(case)
            .or_else(|| self.pubsub.namespace_sessions.epoch(case))
            .or_else(|| self.request_contracts.request_times(case).target)
    }

    pub(in crate::replay) fn needs_ingress_events(&self, case: &str) -> bool {
        self.pubsub.ingress.needs_native_events(case)
    }

    pub(in crate::replay) fn needs_native_events(&self, case: &str) -> bool {
        self.needs_ingress_events(case)
            || self.pubsub.native_clock.needs_observer(case)
            || self.pubsub.namespace_sessions.needs_observer(case)
    }

    pub(in crate::replay) fn native_events_begin(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
    ) -> bool {
        let enabled = self.needs_native_events(case);
        if self.pubsub.native_clock.observe_begin(case, epoch).is_err() {
            return false;
        }
        if self
            .pubsub
            .namespace_sessions
            .observe_begin(case, epoch)
            .is_err()
        {
            return false;
        }
        self.pubsub.ingress.observe_begin(case, epoch, enabled)
    }

    pub(in crate::replay) fn observe_native_event(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        event: &NativeEvent,
    ) -> Result<()> {
        self.pubsub.ingress.observe(case, epoch, event)
    }
}

pub(super) fn prerequisites(
    exchanges: &[ReplayExchange],
    case: &str,
    key: &Key,
    started: DateTime<Utc>,
    before: DateTime<Utc>,
) -> Result<Vec<Prerequisite>> {
    let mut prior = Vec::new();
    for (index, exchange) in exchanges.iter().enumerate() {
        if exchange.source != ReplaySource::Case
            || exchange.case_id.as_deref() != Some(case)
            || exchange.shared_rule_id.is_some()
            || exchange.record.target_port != key.0.port
            || normalize_host(&exchange.record.target_host) != key.0.host
            || exchange.record.command != "PUBLISH"
            || exchange.args.len() != 2
            || exchange.args[0] != key.1
        {
            continue;
        }
        // A floored duration gives an upper bound on request start. Requiring
        // that bound before ingress proves the edge; its earlier lower bound
        // would invent ordering when the two clocks overlap within one ms.
        let Some(timestamp) = exchange.record.started_at() else {
            continue;
        };
        if timestamp < started || timestamp >= before {
            continue;
        }
        let value = if let Some(request) = rpc::request("PUBLISH", &exchange.args)? {
            request.value
        } else if let Some(broadcast) = rpc::broadcast("PUBLISH", &exchange.args)? {
            broadcast.value
        } else {
            continue;
        };
        if value["room"] != key.2.sid || value["namespace"] != key.2.namespace {
            continue;
        }
        ensure!(
            exchange.record.replay_safe
                && exchange.record.outcome == DependencyExchangeOutcome::Response,
            "unsafe remote Socket.IO causal prefix"
        );
        ensure!(
            prior.len() < 4096,
            "remote Socket.IO causal prefix exceeds bound"
        );
        prior.push((
            timestamp,
            (exchange.record.connection_id, exchange.record.sequence),
            index,
            value["event"]
                .as_str()
                .context("native event name missing")?
                .to_owned(),
        ));
    }
    prior.sort_by_key(|(timestamp, wire, _, _)| (*timestamp, *wire));
    let mut counts = HashMap::<String, u64>::new();
    Ok(prior
        .into_iter()
        .map(|(_, wire, exchange_index, event)| {
            let count = counts.entry(event.clone()).or_default();
            *count += 1;
            Prerequisite {
                wire,
                exchange_index,
                event,
                occurrence: *count,
            }
        })
        .collect())
}

impl Ingress {
    fn needs_native_events(&self, case: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.case == case && !entry.prerequisites.is_empty())
    }

    pub(in crate::replay) fn observe_begin(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        enabled: bool,
    ) -> bool {
        if enabled
            && self
                .observed
                .as_ref()
                .is_none_or(|live| live.case != case || live.epoch != epoch)
        {
            self.observed = Some(LiveEvents {
                case: case.into(),
                epoch,
                ordinals: HashMap::new(),
                counts: HashMap::new(),
            });
        }
        enabled
    }

    pub(in crate::replay) fn observe(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        event: &NativeEvent,
    ) -> Result<()> {
        ensure!(
            !event.namespace.is_empty()
                && event.namespace.len() <= 1024
                && !event.event.is_empty()
                && event.event.len() <= 1024,
            "invalid native event metadata"
        );
        let live = self
            .observed
            .as_mut()
            .context("native event observer was not admitted")?;
        ensure!(
            live.case == case && live.epoch == epoch,
            "native event observer epoch changed"
        );
        // The number of observations does not grow this inventory: each live
        // namespace retains one ordinal, and event counts below retain only
        // immutable Source prerequisite names. Bound that metadata rather than
        // rejecting a valid long-lived stream after a fixed number of events.
        ensure!(
            live.ordinals.contains_key(&event.namespace) || live.ordinals.len() < 64,
            "native event observation exceeds bound"
        );
        let previous = live.ordinals.entry(event.namespace.clone()).or_default();
        ensure!(
            Some(event.ordinal) == previous.checked_add(1),
            "native event observation is not sequential"
        );
        *previous = event.ordinal;
        // Keep only metadata needed by immutable Source request prerequisites.
        if self.entries.iter().any(|entry| {
            entry.case == case
                && entry.source.namespace == event.namespace
                && entry
                    .prerequisites
                    .iter()
                    .any(|prior| prior.event == event.event)
        }) {
            let count = live
                .counts
                .entry((event.namespace.clone(), event.event.clone()))
                .or_default();
            *count = count
                .checked_add(1)
                .context("native event prerequisite count exceeds range")?;
        }
        Ok(())
    }

    pub(super) fn causal_ready(
        &self,
        entry: &Entry,
        epoch: DateTime<Utc>,
        exchanges: &[ReplayExchange],
    ) -> bool {
        if entry.prerequisites.is_empty() {
            return true;
        }
        let Some(live) = &self.observed else {
            return false;
        };
        live.case == entry.case
            && live.epoch == epoch
            && entry.prerequisites.iter().all(|prior| {
                live.counts
                    .get(&(entry.source.namespace.clone(), prior.event.clone()))
                    .copied()
                    .unwrap_or(0)
                    >= prior.occurrence
                    && exchanges.get(prior.exchange_index).is_some_and(|exchange| {
                        exchange.source == ReplaySource::Case
                            && exchange.case_id.as_deref() == Some(&entry.case)
                            && (exchange.record.connection_id, exchange.record.sequence)
                                == prior.wire
                            && exchange.status.is_consumed()
                    })
            })
    }
}
