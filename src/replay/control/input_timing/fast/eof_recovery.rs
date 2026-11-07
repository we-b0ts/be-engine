//! A terminal Redis lane wait may be released by Target's real disconnect callback.
use super::*;
use crate::replay::{
    admission::RequestAdmission,
    report::command::{CommandMatchDiagnostic, CommandRequestReport},
};

const PROOF_BUDGET: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub(in crate::replay) struct EofRecovery {
    observing: bool,
    probe: Option<Probe>,
}

#[derive(Debug)]
struct Probe {
    prefix_end: usize,
    blocker_index: usize,
    blocker: RecordedReference,
    rejection: CommandRequestReport,
    offered_at: Option<(MonoInstant, DateTime<Utc>)>,
    observed_at: Option<DateTime<Utc>>,
    verified_close_at: Option<DateTime<Utc>>,
}

fn delivered(state: &ReplayState, handle: ExchangeHandle) -> bool {
    handle.delivery_state(state) == Some(ReplayExchangeStatus::Consumed)
        || handle.permits_unstarted_omission(state, false, true)
}

pub(in crate::replay) fn propose_eof_recovery(
    state: &mut ReplayState,
    observation: &RequestAdmission,
    rejection: &CommandRequestReport,
) -> bool {
    let Some(probe) = candidate(state, observation, rejection) else {
        return false;
    };
    state
        .input_timing
        .as_mut()
        .expect("eligible timeline")
        .eof_recovery
        .probe = Some(probe);
    true
}

fn candidate(
    state: &ReplayState,
    observation: &RequestAdmission,
    rejection: &CommandRequestReport,
) -> Option<Probe> {
    let live = state.input_timing.as_ref()?;
    if !live.eof_recovery.observing
        || live.eof_recovery.probe.is_some()
        || observation.cancel_reason(state).is_some()
        || live.admission_epoch != state.admission_epoch
        || observation.case.as_deref() != Some(live.case.as_str())
        || crate::replay::control::case_execution::failed(state, &live.case)
        || !state
            .dependency_tails
            .permits_eof_recovery(state, &live.case)
    {
        return None;
    }
    let CommandMatchDiagnostic::LaneBlocked {
        candidate,
        blocked_by,
    } = rejection.diagnostic.as_ref()?
    else {
        return None;
    };
    if candidate.command != "PUBLISH" || blocked_by.command != "GET" {
        return None;
    }
    let plan = live.fast.as_ref()?;
    let tail = plan.source.tail.as_ref()?;
    let region = tail.heartbeat_timeout_us?..tail.heartbeat_dependency_cutoff_us?;
    let count = plan.heartbeat_request_count?;
    let source_ref =
        |r: &crate::replay::report::command::CommandExchangeRefReport| RecordedReference::Redis {
            connection_id: r.connection_id,
            sequence: r.sequence,
        };
    let blocker = source_ref(blocked_by);
    let held = source_ref(candidate);
    let requests = &plan.source.requests[..count];
    let prefix_end = requests
        .iter()
        .position(|request| request.reference == blocker)?;
    let held = requests.iter().find(|request| request.reference == held)?;
    let start = requests[prefix_end].started_us;
    if !region.contains(&start)
        || held.started_us <= start
        || requests
            .get(prefix_end + 1)
            .is_some_and(|next| next.started_us == start)
        || !plan.handles[..prefix_end]
            .iter()
            .all(|&handle| delivered(state, handle))
    {
        return None;
    }
    let ExchangeHandle::Native(DependencyAdapter::Redis(blocker_index)) = plan.handles[prefix_end]
    else {
        return None;
    };
    Some(Probe {
        prefix_end,
        blocker_index,
        blocker,
        rejection: rejection.clone(),
        offered_at: None,
        observed_at: None,
        verified_close_at: None,
    })
}

pub(super) fn offer(state: &mut ReplayState) -> Option<Value> {
    let live = state.input_timing.as_mut()?;
    live.eof_recovery.observing = true;
    let probe = live.eof_recovery.probe.as_mut()?;
    if probe.offered_at.is_some() {
        return None;
    }
    probe.offered_at = Some((MonoInstant::now(), Utc::now()));
    tracing::info!(case_id = live.case, blocker = ?probe.blocker,
        "offering Socket.IO EOF recovery for a timed-out Redis lane");
    Some(
        serde_json::json!({"ok":true,"ready":true,"advance":Advance {
        removed_ms:live.clock.removed_ms(),probe_eof:true}}),
    )
}

pub(in crate::replay) fn observe_eof_blocker(
    state: &mut ReplayState,
    observation: &RequestAdmission,
    index: usize,
    received_at: DateTime<Utc>,
) {
    if let Some(live) = &mut state.input_timing
        && live.admission_epoch == state.admission_epoch
        && observation.case.as_deref() == Some(&live.case)
        && let Some(probe) = &mut live.eof_recovery.probe
        && probe.offered_at.is_some()
        && probe.blocker_index == index
    {
        probe.observed_at = Some(received_at);
    }
}

pub(in crate::replay) fn confirm_eof_recovery(
    state: &mut ReplayState,
    case: &str,
    closed_at: Option<DateTime<Utc>>,
) -> Result<Value> {
    let live = state
        .input_timing
        .as_ref()
        .context("missing EOF recovery timeline")?;
    let probe = live
        .eof_recovery
        .probe
        .as_ref()
        .context("missing EOF recovery offer")?;
    if let Some(verified) = probe.verified_close_at {
        ensure!(
            closed_at == Some(verified),
            "verified EOF recovery timestamp changed"
        );
        return Ok(serde_json::json!({"ok":true,"recovered":true}));
    }
    let (offered, offered_at) = probe.offered_at.context("EOF recovery was not offered")?;
    // A transport close attempt also opens the usual Case attribution window
    // when the proof fails, so late cleanup cannot leak into the next Case.
    crate::replay::control::case_cleanup::mark_client_aborted(state, case)?;
    let live = state.input_timing.as_ref().expect("validated EOF timeline");
    let probe = live
        .eof_recovery
        .probe
        .as_ref()
        .expect("validated EOF offer");
    let failed = closed_at.is_none_or(|closed| closed < offered_at || closed > Utc::now())
        || offered.elapsed() >= PROOF_BUDGET
        || probe
            .observed_at
            .zip(closed_at)
            .is_some_and(|(observed, closed)| observed <= closed)
        || crate::replay::control::case_execution::failed(state, case);
    if failed {
        reject(state);
        return Ok(serde_json::json!({"ok":true,"recovered":false}));
    }
    let delivered = state.redis.timing_delivered(
        case,
        live.admission_epoch,
        DeliveryReference::RedisResponse(probe.blocker),
    );
    if probe.observed_at.is_none() || !delivered {
        return Ok(serde_json::json!({"ok":true,"wait_ms":POLL_MS}));
    }
    let plan = live.fast.as_ref().expect("EOF recovery requires fast plan");
    for &handle in plan.eof_recovery_suffix(probe.prefix_end) {
        if let ExchangeHandle::Native(DependencyAdapter::Redis(index)) = handle {
            state.redis.open_socketio_eof_suffix(index);
        }
    }
    state.redis.notify_socketio_eof_suffix();
    let probe = state
        .input_timing
        .as_mut()
        .expect("validated EOF timeline")
        .eof_recovery
        .probe
        .as_mut()
        .expect("validated EOF offer");
    probe.verified_close_at = closed_at;
    tracing::info!(case_id = case, blocker = ?probe.blocker, ?closed_at,
        observed_at = ?probe.observed_at, "verified Socket.IO disconnect dependency");
    Ok(serde_json::json!({"ok":true,"recovered":true}))
}

impl Plan {
    fn eof_recovery_suffix(&self, prefix_end: usize) -> &[ExchangeHandle] {
        // The recording can retain shutdown traffic beyond its wire EOF for
        // attribution. That traffic is outside the verified prefix as well.
        &self.handles[prefix_end + 1..]
    }
}

fn reject(state: &mut ReplayState) {
    if let Some(probe) = state
        .input_timing
        .as_mut()
        .and_then(|live| live.eof_recovery.probe.take())
    {
        state.redis.record_unmatched_request(probe.rejection);
    }
}

pub(in crate::replay) fn finish_eof_recovery(state: &mut ReplayState, case: &str) {
    let Some(live) = state.input_timing.as_mut().filter(|live| live.case == case) else {
        return;
    };
    let Some(probe) = live.eof_recovery.probe.take() else {
        return;
    };
    let Some(close_at) = probe.verified_close_at else {
        state.redis.record_unmatched_request(probe.rejection);
        return;
    };
    let plan = live.fast.as_ref().expect("EOF recovery requires fast plan");
    let first_after_source_eof = plan.heartbeat_request_count.expect("heartbeat EOF prefix");
    let suffix = plan.eof_recovery_suffix(probe.prefix_end).to_vec();
    let clean = !crate::replay::control::case_execution::failed(state, case)
        && state.case_cleanup.deadline(case).is_none();
    let mut omitted = 0;
    let mut omitted_after_source_eof = 0;
    for (index, handle) in (probe.prefix_end + 1..).zip(suffix) {
        if handle.settle_socketio_eof_suffix(state, clean) {
            omitted += 1;
            omitted_after_source_eof += usize::from(index >= first_after_source_eof);
        }
    }
    state.dependency_tails.record_eof_recovery(
        case,
        serde_json::json!({
            "closed_at": close_at,
            "blocker": probe.blocker,
            "blocker_observed_at": probe.observed_at,
            "interrupted_request": probe.rejection,
            "omitted_unstarted_suffix": omitted,
            "omitted_after_source_eof": omitted_after_source_eof,
        }),
    );
}
