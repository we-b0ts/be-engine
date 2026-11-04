//! Active-case timing grants share a monotonic clock with native dependency inputs.
use super::*;
use crate::interaction::replay::timing::{
    Advance, Clock, SocketIoTiming, cancellation, delivery_prefix,
};
use crate::replay::control::dependency_tail::RecordedReference;
use tokio::time::Instant as MonoInstant;
mod client;
mod source;
pub(crate) use client::connect;

#[derive(Debug)]
struct SourcePlanUnavailable;

impl std::fmt::Display for SourcePlanUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("input timing Source evidence could not be prepared")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::replay) enum DeliveryReference {
    RedisResponse(RecordedReference),
    NativePush(redis::pubsub::PushId),
}

#[derive(Debug)]
pub(in crate::replay) struct Evidence {
    pub reference: DeliveryReference,
    pub completed_at: DateTime<Utc>,
    /// Native effects retain their own retiming/coverage authority. They can
    /// authorize compression after actual coverage, without adding a new hard
    /// predecessor to a later business input.
    pub individual: bool,
}

#[derive(Debug)]
pub(in crate::replay) struct Live {
    case: String,
    epoch: DateTime<Utc>,
    admission_epoch: u64,
    started: MonoInstant,
    clock: Clock,
    plan: source::Plan,
    mode: SocketIoTiming,
    evidence: Vec<Evidence>,
    advanced: BTreeSet<u64>,
}

impl Live {
    /// None leaves unrelated or unsupported native scheduling unchanged.
    pub(in crate::replay) fn reached(
        &self,
        case: &str,
        epoch: DateTime<Utc>,
        offset: chrono::TimeDelta,
    ) -> Option<bool> {
        if self.case != case || self.epoch != epoch {
            return None;
        }
        let offset = u64::try_from(offset.num_milliseconds()).ok()?;
        Some(self.started.elapsed() >= Duration::from_millis(self.clock.effective_ms(offset)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::replay) struct Query {
    pub(super) epoch: DateTime<Utc>,
    pub(super) sequence: u64,
    pub(super) completed: Vec<u64>,
}

pub(super) async fn accept(
    request: &ReplayControlRequest,
    shared: &Arc<Mutex<ReplayState>>,
) -> Value {
    let result = async {
        let case = request
            .case_id
            .as_deref()
            .context("input timing requires case_id")?;
        if request.command == "input_timing_begin" {
            let recording = {
                let state = shared.lock().await;
                ensure_live(&state, case)?;
                state
                    .cases
                    .get(case)
                    .context("input timing case missing")?
                    .clone()
            };
            let plan = tokio::task::spawn_blocking(move || source::load(&recording))
                .await
                .context(SourcePlanUnavailable)?
                .context(SourcePlanUnavailable)?;
            let mut state = shared.lock().await;
            ensure_live(&state, case)?;
            ensure!(
                state.input_timing.is_none(),
                "input timing already admitted"
            );
            let epoch = state
                .redis
                .pubsub
                .native_clock
                .epoch(case)
                .or_else(|| state.redis.request_contracts.request_times(case).target)
                .unwrap_or_else(Utc::now);
            let (mut evidence, covered) = match plan.source_start {
                Some(start) => state.redis.timing_evidence(case, start)?,
                None => (Vec::new(), false),
            };
            // Keep immutable metadata ordered independently of the wire-success
            // journal. Delivery hooks do not rescan this inventory per push.
            evidence.sort_unstable_by_key(|entry| entry.reference);
            let plan = source::Plan {
                covered: plan.covered && covered,
                ..plan
            };
            let mode = request.socketio_timing.unwrap_or_default();
            let candidates = plan
                .input
                .actions
                .iter()
                .filter(|action| action.compressible_gap && !cancellation(action))
                .count();
            tracing::info!(
                case_id = case,
                ?mode,
                candidates,
                dependency_timing_covered = plan.covered,
                "prepared Socket.IO input timeline"
            );
            state.input_timing = Some(Live {
                case: case.into(),
                epoch,
                admission_epoch: state.admission_epoch,
                started: MonoInstant::now(),
                clock: Clock::default(),
                plan,
                mode,
                evidence,
                advanced: BTreeSet::new(),
            });
            return Ok(serde_json::json!({"ok":true,"epoch":epoch}));
        }
        let query = request
            .input_timing
            .as_ref()
            .context("input timing metadata missing")?;
        let mut state = shared.lock().await;
        ensure_live(&state, case)?;
        let live = state
            .input_timing
            .as_ref()
            .context("input timeline not admitted")?;
        ensure!(
            live.case == case
                && live.epoch == query.epoch
                && live.admission_epoch == state.admission_epoch,
            "input timing request epoch changed"
        );
        let action = live
            .plan
            .input
            .actions
            .iter()
            .find(|action| action.sequence == query.sequence)
            .context("input timing sequence outside original program")?;
        ensure!(
            query.completed.len() <= action.after.len()
                && query.completed.iter().all(|id| action.after.contains(id)),
            "input completion outside original prerequisites"
        );
        let cutoff = live.plan.source_start.and_then(|start| {
            start.checked_add_signed(chrono::TimeDelta::milliseconds(
                i64::try_from(action.offset_ms).ok()?,
            ))
        });
        let delivered = |e: &Evidence| {
            state
                .redis
                .timing_delivered(case, live.admission_epoch, e.reference)
                || match e.reference {
                    DeliveryReference::RedisResponse(reference) => {
                        dependency_tail::timing_optional(&state, case, reference)
                    }
                    DeliveryReference::NativePush(_) => false,
                }
        };
        let ready = live
            .evidence
            .iter()
            .filter(|e| cutoff.is_some_and(|cutoff| e.completed_at < cutoff))
            .all(&delivered);
        let prefix_ready = live
            .evidence
            .iter()
            .filter(|e| e.individual && cutoff.is_some_and(|cutoff| e.completed_at < cutoff))
            .all(delivered);
        // Input offsets are floor milliseconds. A completion in that same
        // millisecond cannot prove whether it precedes or follows this input.
        let boundary_clear = cutoff.is_some_and(|cutoff| {
            live.evidence.iter().all(|e| {
                e.completed_at < cutoff
                    || e.completed_at >= cutoff + chrono::TimeDelta::milliseconds(1)
            })
        });
        let live = state.input_timing.as_mut().expect("validated timeline");
        let action = live
            .plan
            .input
            .actions
            .iter()
            .find(|action| action.sequence == query.sequence)
            .expect("validated sequence");
        let elapsed = u64::try_from(live.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let eligible = live.mode == SocketIoTiming::Auto
            && live.plan.covered
            && boundary_clear
            && !live.plan.input.policy.preserve_input_timing
            && action.compressible_gap
            && !cancellation(action)
            && action.after.iter().all(|id| query.completed.contains(id))
            && !live
                .plan
                .input
                .socket_io_heartbeat
                .as_ref()
                .is_some_and(|h| h.responses.is_empty());
        if eligible && ready && live.advanced.insert(action.sequence) {
            let before = live.clock.removed_ms();
            live.clock.compress(
                action.gap_start_ms.expect("validated compressible gap"),
                action.offset_ms,
                elapsed,
                live.plan.input.policy.input_gap_ms,
            );
            tracing::debug!(
                case_id = case,
                sequence = action.sequence,
                removed_ms = live.clock.removed_ms() - before,
                "committed Socket.IO idle compression after actual dependency delivery"
            );
        }
        let remaining = live
            .clock
            .effective_ms(action.offset_ms)
            .saturating_sub(elapsed);
        // Source dependencies completed strictly before this input form its
        // finite delivery prefix. Slow Target handling must not turn that input
        // into an earlier observation. Coverage of other protocols is required
        // for compression, not for honoring these independently proven edges.
        // Only business events wait: native ACKs can complete an RPC in this
        // prefix, and protocol heartbeat/cancellation remain independent.
        let prefix_pending = live.mode == SocketIoTiming::Auto
            && !live.plan.input.policy.preserve_input_timing
            && cutoff.is_some()
            && delivery_prefix(action)
            && !prefix_ready;
        let retry = if prefix_pending {
            10
        } else if eligible && !ready {
            remaining.min(10)
        } else {
            remaining
        };
        Ok::<_, anyhow::Error>(
            serde_json::json!({"ok":true,"wait_ms":retry,"ready":remaining==0 && !prefix_pending,
            "advance":Advance {removed_ms:live.clock.removed_ms()}}),
        )
    }
    .await;
    result.unwrap_or_else(|error| {
        let reason = if error.is::<SourcePlanUnavailable>() {
            "input_timing_source_unavailable"
        } else {
            "input_timing_rejected"
        };
        serde_json::json!({"ok":false,"reason":reason,"error":error.to_string()})
    })
}

fn ensure_live(state: &ReplayState, case: &str) -> Result<()> {
    ensure!(
        state.active_case_id.as_deref() == Some(case)
            && state.finalized_at.is_none()
            && !state.target_session_stopped,
        "input timing requires the active live case"
    );
    Ok(())
}
