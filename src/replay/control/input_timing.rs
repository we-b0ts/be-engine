//! Active-case timing grants share a monotonic clock with native dependency inputs.
use super::*;
use crate::interaction::replay::timing::{
    Advance, Clock, SocketIoTiming, cancellation, delivery_prefix,
};
use crate::replay::control::dependency_tail::RecordedReference;
use tokio::time::Instant as MonoInstant;
mod client;
mod fast;
mod source;
pub(crate) use client::connect;

#[derive(Debug)]
pub(in crate::replay) struct PreparedSource {
    case: String,
    plan: Result<source::Plan>,
}

impl PreparedSource {
    pub(in crate::replay) fn load(
        recording: &ReplayCase,
        fast_cap: Option<u64>,
        dependencies: Option<&[u8]>,
    ) -> Self {
        Self {
            case: recording.id.clone(),
            plan: source::load(recording, fast_cap, dependencies),
        }
    }
}

pub(in crate::replay) async fn prepare_source(
    shared: &Arc<Mutex<ReplayState>>,
    case: &str,
) -> Result<()> {
    let (recording, fast_cap) = {
        let state = shared.lock().await;
        if state
            .prepared_socketio_input
            .as_ref()
            .is_some_and(|prepared| prepared.case == case)
        {
            return Ok(());
        }
        let recording = state.cases.get(case).context("input timing case missing")?;
        (recording.clone(), source_fast_cap(&state))
    };
    let prepared =
        tokio::task::spawn_blocking(move || PreparedSource::load(&recording, fast_cap, None))
            .await
            .context(SourcePlanUnavailable)?;
    shared.lock().await.prepared_socketio_input = Some(prepared);
    Ok(())
}

pub(in crate::replay) fn source_fast_cap(state: &ReplayState) -> Option<u64> {
    (state.stream_timing == Some(ReplayStreamTiming::Fast)).then_some(state.stream_interval_cap_ms)
}

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
    fast: Option<fast::Plan>,
    native_dispatch: Option<fast::NativeDispatch>,
    native_push_times: Option<Vec<DateTime<Utc>>>,
}

impl Live {
    pub(in crate::replay) fn heartbeat_close_window(
        &self,
        case: &str,
    ) -> Option<(DateTime<Utc>, MonoInstant)> {
        if self.case != case {
            return None;
        }
        Some((
            self.fast.as_ref()?.heartbeat_close_at()?,
            self.started + crate::replay::FAST_CASE_TIMEOUT,
        ))
    }

    pub(in crate::replay) fn mysql_dispatch_prefix(
        &self,
        case: &str,
    ) -> Option<std::ops::Range<DateTime<Utc>>> {
        if self.case != case {
            return None;
        }
        self.fast.as_ref()?.mysql_dispatch_prefix(self)
    }

    pub(in crate::replay) fn mysql_candidate_anchor(
        &self,
        case: &str,
        last_matched: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        if self.case != case {
            return None;
        }
        self.fast
            .as_ref()?
            .mysql_candidate_anchor(self, last_matched)
    }

    pub(in crate::replay) fn mysql_candidate_cutoff(
        &self,
        case: &str,
        anchor: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        if self.case != case {
            return None;
        }
        self.fast.as_ref()?.mysql_candidate_cutoff(self, anchor)
    }

    pub(in crate::replay) fn mysql_prefix_window(
        &self,
        case: &str,
        request_at: DateTime<Utc>,
    ) -> Option<(usize, usize)> {
        if self.case != case || self.fast.is_none() {
            return None;
        }
        let pushes = self.native_push_times.as_ref()?;
        let us = u64::try_from((request_at - self.plan.source_start?).num_microseconds()?).ok()?;
        let actions = &self.plan.input.actions;
        let boundary = actions.partition_point(|action| action.offset_ms <= us / 1000);
        // Leave the legacy millisecond boundary ambiguous, as dispatch does.
        let push_boundary = pushes.partition_point(|&push| push < request_at);
        (pushes.get(push_boundary) != Some(&request_at)
            && (boundary == 0 || actions[boundary - 1].offset_ms < us / 1000))
            .then_some((boundary, push_boundary))
    }

    pub(in crate::replay) fn native_fast_setup_ready(&self, state: &ReplayState) -> bool {
        self.fast
            .as_ref()
            .is_some_and(|plan| plan.native_fast_setup_ready(state, &self.case))
    }

    pub(in crate::replay) fn native_dispatch_cap(
        &self,
        state: &ReplayState,
        case: &str,
        epoch: DateTime<Utc>,
        offset: chrono::TimeDelta,
    ) -> Option<Duration> {
        if self.case != case || self.epoch != epoch {
            return None;
        }
        self.fast
            .as_ref()?
            .native_dispatch_cap(state, case, self.native_dispatch?, offset)
    }

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) events_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) closed_at: Option<DateTime<Utc>>,
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
            let mode = request.socketio_timing.unwrap_or_default();
            let mut state = shared.lock().await;
            ensure_live(&state, case)?;
            ensure!(
                state.input_timing.is_none(),
                "input timing already admitted"
            );
            let mut plan = state
                .prepared_socketio_input
                .take()
                .filter(|prepared| prepared.case == case)
                .context(SourcePlanUnavailable)?
                .plan
                .context(SourcePlanUnavailable)?;
            let epoch = state
                .redis
                .native_request_epoch(case)
                .unwrap_or_else(Utc::now);
            let fast = plan
                .fast
                .take()
                .filter(|_| mode == SocketIoTiming::Auto)
                .and_then(|source| source.resolve(&mut state, case, &plan.input).ok());
            let fast_tail = fast.as_ref().and_then(fast::Plan::tail);
            let ordered_fast = fast.is_some();
            let native_push_times = plan.source_start.filter(|_| ordered_fast).and_then(|start| {
                let (pushes, covered) = state.redis.pubsub.timing_evidence(case, start);
                covered.then(|| {
                    let mut times: Vec<_> = pushes.into_iter().map(|push| push.completed_at).collect();
                    times.sort_unstable();
                    times
                })
            });
            let (mut evidence, covered) = match (fast.is_some(), plan.source_start) {
                (true, _) => (Vec::new(), false),
                (false, Some(start)) => state.redis.timing_evidence(case, start)?,
                (false, None) => (Vec::new(), false),
            };
            evidence.sort_unstable_by_key(|entry| entry.completed_at);
            let plan = source::Plan {
                covered: plan.covered && covered,
                ..plan
            };
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
                ordered_fast,
                heartbeat_tail_eligible = fast_tail.as_ref().is_some_and(|tail| tail.heartbeat_timeout),
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
                fast,
                native_dispatch: None,
                native_push_times,
            });
            return Ok(serde_json::json!({"ok":true,"epoch":epoch,"ordered_fast":ordered_fast,"fast_tail":fast_tail}));
        }
        let query = request
            .input_timing
            .as_ref()
            .context("input timing metadata missing")?;
        let waiting_for_state = MonoInstant::now();
        let mut state = shared.lock().await;
        let state_wait = waiting_for_state.elapsed();
        if state_wait >= Duration::from_millis(250) {
            tracing::warn!(
                case_id = case,
                sequence = query.sequence,
                state_wait_ms = state_wait.as_millis(),
                "Socket.IO input feedback waited for Replay state"
            );
        }
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
        if request.command == "input_timing_native_prefix" {
            let active = state.redis.pubsub.native_clock.fast_prefix_active(
                case,
                live.epoch,
                MonoInstant::now(),
            );
            return Ok(serde_json::json!({"ok":true,"active":active}));
        }
        if live.fast.is_some() {
            return fast::advance(&mut state, request.command == "input_timing_tail", query);
        }
        let action_index = live
            .plan
            .input
            .actions
            .iter()
            .position(|action| action.sequence == query.sequence)
            .context("input timing sequence outside original program")?;
        let action = &live.plan.input.actions[action_index];
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
        let prefix_end = cutoff.map_or(0, |cutoff| {
            live.evidence
                .partition_point(|e| e.completed_at < cutoff)
        });
        let prefix = &live.evidence[..prefix_end];
        // Input offsets are floor milliseconds. A completion in that same
        // millisecond cannot prove whether it precedes or follows this input.
        let boundary_clear = cutoff.is_some_and(|cutoff| {
            live.evidence.get(prefix_end).is_none_or(|e| {
                e.completed_at >= cutoff + chrono::TimeDelta::milliseconds(1)
            })
        });
        let auto = live.mode == SocketIoTiming::Auto && !live.plan.input.policy.preserve_input_timing;
        let eligible = auto
            && live.plan.covered
            && boundary_clear
            && action.compressible_gap
            && !cancellation(action)
            && action.after.iter().all(|id| query.completed.contains(id))
            && !live
                .plan
                .input
                .socket_io_heartbeat
                .as_ref()
                .is_some_and(|h| h.responses.is_empty());
        let ready = eligible && prefix.iter().all(&delivered);
        let prefix_pending = auto
            && cutoff.is_some()
            && delivery_prefix(action)
            && !prefix.iter().filter(|e| e.individual).all(delivered);
        let live = state.input_timing.as_mut().expect("validated timeline");
        let action = &live.plan.input.actions[action_index];
        let elapsed = u64::try_from(live.started.elapsed().as_millis()).unwrap_or(u64::MAX);
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
        let retry = if prefix_pending {
            10
        } else if eligible && !ready {
            remaining.min(10)
        } else {
            remaining
        };
        Ok::<_, anyhow::Error>(
            serde_json::json!({"ok":true,"wait_ms":retry,"ready":remaining==0 && !prefix_pending,
            "advance":Advance {removed_ms:live.clock.removed_ms(), ..Advance::default()}}),
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
