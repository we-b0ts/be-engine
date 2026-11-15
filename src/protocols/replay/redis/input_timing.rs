//! Redis timing projection and the distinct response-written completion fact.
use super::*;
use crate::replay::control::input_timing::{DeliveryReference, Evidence};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeliveryScope {
    case: String,
    epoch: u64,
}

/// Actual native writes survive timing-observer admission. A new request/Case
/// epoch cannot borrow earlier delivery, even when its textual Case ID is reused.
#[derive(Debug, Default)]
pub(super) struct Deliveries {
    scope: Option<DeliveryScope>,
    written: BTreeSet<DeliveryReference>,
    // Only validated subscription aliases are process-owned setup. Their exact
    // successful reply remains usable by its original Case across request epochs.
    shared_subscriptions: BTreeMap<String, BTreeSet<DeliveryReference>>,
}

pub(super) fn scope(state: &ReplayState) -> Option<DeliveryScope> {
    if state.target_session_stopped || state.finalized_at.is_some() {
        return None;
    }
    Some(DeliveryScope {
        case: state.active_case_id.clone()?,
        epoch: state.admission_epoch(),
    })
}

/// Call only after successful native TCP delivery and its contract commits.
pub(super) fn delivered(
    state: &mut ReplayState,
    captured: Option<&DeliveryScope>,
    reference: DeliveryReference,
) {
    let Some(captured) = captured else {
        return;
    };
    if scope(state).as_ref() != Some(captured) {
        return;
    }
    let receipts = &mut state.protocols.redis.timing_deliveries;
    if receipts.scope.as_ref() != Some(captured) {
        receipts.scope = Some(captured.clone());
        receipts.written.clear();
    }
    receipts.written.insert(reference);
}

impl RedisReplayState {
    pub(crate) fn timing_delivered(
        &self,
        case: &str,
        epoch: u64,
        reference: &DeliveryReference,
    ) -> bool {
        self.timing_deliveries
            .shared_subscriptions
            .get(case)
            .is_some_and(|references| references.contains(reference))
            || self
                .timing_deliveries
                .scope
                .as_ref()
                .is_some_and(|scope| scope.case == case && scope.epoch == epoch)
                && self.timing_deliveries.written.contains(reference)
    }

    pub(crate) fn timing_evidence(
        &mut self,
        case: &str,
        start: DateTime<Utc>,
    ) -> Result<(Vec<Evidence>, bool)> {
        // Source ownership must be established before freezing timing metadata,
        // even when no Target command has triggered lazy native preparation yet.
        self.prepare_observations(case)?;
        self.prepare_read_commutation(case)?;
        self.prepare_append_case(case)?;
        self.prepare_activity_case(case)?;
        let mut evidence = Vec::new();
        let mut covered = true;
        for (index, exchange) in
            self.exchanges.iter().enumerate().filter(|(_, e)| {
                e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case)
            })
        {
            let record = &exchange.record;
            if record.lifecycle_cleanup
                || record.native.session_setup
                || exchange.reusable_snapshot
                || record.native.cache_snapshot_hit
                // A proven transient observation may be omitted. It is not a
                // delivery prerequisite and never receives a wire-success receipt.
                || exchange.optional_observation_rule.is_some()
            {
                continue;
            }
            let Some(at) = record.native.timestamp else {
                covered = false;
                continue;
            };
            if at < start {
                continue;
            }
            if record.native.outcome != DependencyExchangeOutcome::Response {
                covered = false;
                continue;
            }
            evidence.push(Evidence {
                reference: DeliveryReference::Exchange(record.cleanup_reference()),
                completed_at: at,
                individual: exchange.observation_rule.is_none()
                    && exchange.read_commutation_rule.is_none()
                    && exchange.shared_rule_id.is_none()
                    && !exchange.subscription_alias
                    && !self.append_stream_owns(index),
            });
        }
        let (pushes, pushes_covered) = self.pubsub.timing_evidence(case, start);
        evidence.extend(pushes);
        Ok((evidence, covered && pushes_covered))
    }
}

pub(super) fn response_delivered(
    state: &mut ReplayState,
    matched: &MatchedRedisExchange,
    scope: Option<&DeliveryScope>,
) {
    let exchange = &state.protocols.redis.exchanges[matched.index];
    if exchange.source != ReplaySource::Case {
        return;
    }
    let reference = DeliveryReference::Exchange(exchange.record.cleanup_reference());
    if exchange.subscription_alias
        && matches!(
            exchange.record.native.command.as_str(),
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
        )
        && exchange.record.native.outcome == DependencyExchangeOutcome::Response
        && exchange.record.native.response_kind == "array"
        && !state.target_session_stopped
        && state.finalized_at.is_none()
        && let Some(case) = exchange.case_id.as_ref()
    {
        // subscription_alias is installed only after the native owner proves a
        // successful original confirmation and its exact Global subscription
        // requirement/mirror. This hook adds the independent actual TCP write.
        state
            .protocols
            .redis
            .timing_deliveries
            .shared_subscriptions
            .entry(case.clone())
            .or_default()
            .insert(reference);
    }
    response_indices_delivered(state, &[matched.index], scope);
}

/// Native owners supply only original Source slots fully covered by this real
/// successful response. Partial/synthetic coalescing state is not a write proof.
pub(super) fn response_indices_delivered(
    state: &mut ReplayState,
    indices: &[usize],
    scope: Option<&DeliveryScope>,
) {
    let Some(captured) = scope else {
        return;
    };
    for index in indices {
        let exchange = &state.protocols.redis.exchanges[*index];
        if exchange.source == ReplaySource::Case
            && exchange.case_id.as_deref() == Some(captured.case.as_str())
        {
            let reference = DeliveryReference::Exchange(exchange.record.cleanup_reference());
            delivered(state, scope, reference);
        }
    }
}

impl crate::replay::protocol_runtime::input::InputTimingProjection for RedisReplayState {
    fn evidence(&mut self, case: &str, start: DateTime<Utc>) -> Result<(Vec<Evidence>, bool)> {
        self.timing_evidence(case, start)
    }

    fn notifications(&self, case: &str, start: DateTime<Utc>) -> (Vec<Evidence>, bool) {
        self.pubsub.timing_evidence(case, start)
    }

    fn delivered(&self, case: &str, epoch: u64, reference: &DeliveryReference) -> bool {
        self.timing_delivered(case, epoch, reference)
    }

    fn prepare_passive(
        &mut self,
        case: &str,
        proof: &crate::interaction::replay::heartbeat_tail::Passive,
        cap_ms: u64,
        setup_finished_ms: u64,
    ) -> bool {
        self.pubsub
            .native_clock
            .prepare_fast(case, proof, cap_ms, setup_finished_ms)
            .is_some()
    }

    fn prefix_active(&self, case: &str, epoch: DateTime<Utc>, now: tokio::time::Instant) -> bool {
        self.pubsub
            .native_clock
            .fast_prefix_active(case, epoch, now)
    }

    fn tail_ready(&mut self, case: &str, now: tokio::time::Instant) -> bool {
        self.pubsub.native_clock.fast_tail_ready(case, now)
    }

    fn plan_dispatch(
        &mut self,
        case: &str,
        epoch: DateTime<Utc>,
        window: std::ops::Range<tokio::time::Duration>,
        cap: tokio::time::Duration,
    ) {
        self.pubsub
            .native_clock
            .plan_dispatch_pace(case, epoch, window, cap);
    }
}
