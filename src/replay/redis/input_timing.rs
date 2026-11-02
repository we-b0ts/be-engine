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
        epoch: state.admission_epoch,
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
    let receipts = &mut state.redis.timing_deliveries;
    if receipts.scope.as_ref() != Some(captured) {
        receipts.scope = Some(captured.clone());
        receipts.written.clear();
    }
    receipts.written.insert(reference);
}

impl RedisReplayState {
    pub(in crate::replay) fn timing_delivered(
        &self,
        case: &str,
        epoch: u64,
        reference: DeliveryReference,
    ) -> bool {
        self.timing_deliveries
            .shared_subscriptions
            .get(case)
            .is_some_and(|references| references.contains(&reference))
            || self
                .timing_deliveries
                .scope
                .as_ref()
                .is_some_and(|scope| scope.case == case && scope.epoch == epoch)
                && self.timing_deliveries.written.contains(&reference)
    }

    pub(in crate::replay) fn timing_evidence(
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
                || record.session_setup
                || exchange.reusable_snapshot
                || record.cache_snapshot_hit
            {
                continue;
            }
            let Some(at) = record.timestamp else {
                covered = false;
                continue;
            };
            if at < start {
                continue;
            }
            if record.outcome != DependencyExchangeOutcome::Response {
                covered = false;
                continue;
            }
            evidence.push(Evidence {
                reference: DeliveryReference::RedisResponse(record.cleanup_reference()),
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
    let exchange = &state.redis.exchanges[matched.index];
    if exchange.source != ReplaySource::Case {
        return;
    }
    let reference = DeliveryReference::RedisResponse(exchange.record.cleanup_reference());
    if exchange.subscription_alias
        && matches!(
            exchange.record.command.as_str(),
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE"
        )
        && exchange.record.outcome == DependencyExchangeOutcome::Response
        && exchange.record.response_kind == "array"
        && !state.target_session_stopped
        && state.finalized_at.is_none()
        && let Some(case) = exchange.case_id.as_ref()
    {
        // subscription_alias is installed only after the native owner proves a
        // successful original confirmation and its exact Global subscription
        // requirement/mirror. This hook adds the independent actual TCP write.
        state
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
        let exchange = &state.redis.exchanges[*index];
        if exchange.source == ReplaySource::Case
            && exchange.case_id.as_deref() == Some(captured.case.as_str())
        {
            let reference = DeliveryReference::RedisResponse(exchange.record.cleanup_reference());
            delivered(state, scope, reference);
        }
    }
}
