//! One frozen timeline for dependency providers and the primary input driver.
pub(super) mod prefetch;
#[cfg(test)]
mod tests;

use super::*;
use std::time::Duration;
use tokio::time::Instant;
use traffic_recording_store::{
    session::PrimaryEventKind,
    session_timeline::{self, SessionTimelineEvent},
};
use traffic_replay::{
    EventKind, SequencePlan, SequenceProgress, SequenceRuntime, SessionPlanEvent, SourceEvent,
};

pub(super) const TIMER_SCOPE: &str = "session";

#[derive(Debug)]
pub(super) struct Session {
    pub(super) runtime: Arc<SequenceRuntime>,
    pub(super) no_progress_timeout: Duration,
    pub(super) prefetch: Option<Arc<prefetch::Responses>>,
    first_failure: Option<Failure>,
}

#[derive(Debug, Clone, Serialize)]
struct Failure {
    expected: Option<SourceEvent>,
    reported_sequence: Option<u64>,
    target_observation_id: Option<Uuid>,
    reason: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    #[serde(flatten)]
    progress: SequenceProgress,
    failure: Option<Failure>,
}

impl Report {
    pub(super) fn complete(&self) -> bool {
        self.progress.complete && self.failure.is_none()
    }

    pub(super) fn failed(&self) -> bool {
        self.progress.failed || self.failure.is_some()
    }
}

impl Session {
    pub(super) fn new(runtime: Arc<SequenceRuntime>, no_progress_timeout: Duration) -> Self {
        Self {
            runtime,
            no_progress_timeout,
            prefetch: None,
            first_failure: None,
        }
    }

    pub(super) fn report(&self) -> Report {
        let progress = self.runtime.progress();
        let failure = self.first_failure.clone().or_else(|| {
            progress.failed.then(|| Failure {
                expected: progress.expected,
                reported_sequence: None,
                target_observation_id: None,
                reason: "recorded dependency delivery or termination failed".into(),
            })
        });
        Report { progress, failure }
    }

    pub(super) fn fail(&mut self, sequence: Option<u64>, observation: Option<Uuid>, reason: &str) {
        if self.first_failure.is_some() {
            return;
        }
        self.first_failure = Some(Failure {
            expected: self.runtime.expected(),
            reported_sequence: sequence,
            target_observation_id: observation,
            reason: reason.chars().take(2048).collect(),
        });
        self.stop_prefetch();
        self.runtime.abort();
    }

    pub(super) fn stop_prefetch(&mut self) {
        if let Some(prefetch) = self.prefetch.take() {
            prefetch.close();
        }
    }

    fn response(&self, error: Option<&str>) -> Value {
        let report = self.report();
        let error = error.or_else(|| {
            report
                .failure
                .as_ref()
                .map(|failure| failure.reason.as_str())
        });
        serde_json::json!({"ok": error.is_none(), "error": error, "session_events": report})
    }
}

pub(super) fn source_scope(source: &Path) -> Result<attribution::Frozen> {
    let (root, manifest) = crate::dependency_index::recording::manifest(source)?;
    ensure!(
        root == source,
        "session Replay requires the sealed recording root"
    );
    ensure!(
        manifest.capture_complete,
        "session recording has incomplete capture coverage"
    );
    ensure!(
        manifest
            .files
            .iter()
            .any(|file| { file.path == traffic_recording_store::session::FILE && file.length > 0 }),
        "sealed recording has no session event journal"
    );
    let inventory = manifest.semantic_inventory;
    ensure!(
        inventory.unsupported_by_scope.is_empty(),
        "session recording has unsupported mandatory dependencies: {:?}",
        inventory.unsupported_by_scope
    );
    ensure!(
        inventory
            .by_owner_kind
            .get("startup")
            .copied()
            .unwrap_or_default()
            == inventory.total_mandatory,
        "session recording has dependencies outside its finite session scope"
    );
    Ok(attribution::Frozen {
        run_value_scopes: BTreeMap::new(),
        snapshot: None,
        startup: Some(crate::dependency_index::recording::dependency_path(&root)),
        process: None,
        unattributed: None,
        batch_scope: None,
    })
}

pub(super) fn plan(
    root: &Path,
    references: BTreeSet<u64>,
    driver_preludes: BTreeSet<u64>,
) -> Result<Arc<SequencePlan>> {
    let (_, manifest) = crate::dependency_index::recording::manifest(root)?;
    ensure!(
        references.is_disjoint(&driver_preludes),
        "driver-prelude exclusion overlaps a scheduled mandatory dependency"
    );
    ensure!(
        usize::try_from(manifest.semantic_inventory.total_mandatory)?
            == references.len() + driver_preludes.len(),
        "session dependencies loaded {} mandatory references and {} proven driver-prelude references, but Source sealed {}",
        references.len(),
        driver_preludes.len(),
        manifest.semantic_inventory.total_mandatory,
    );
    let mut unseen_preludes = driver_preludes;
    let events = session_timeline::read(root)?.filter_map(|row| match row {
        Err(error) => Some(Err(error)),
        Ok(SessionTimelineEvent::Primary(event)) => {
            Some(Ok(SessionPlanEvent::Driver(SourceEvent {
                sequence: event.sequence,
                dependency_sequence: 0,
                offset_micros: event.offset_micros,
                kind: match event.event {
                    PrimaryEventKind::SourceStart => EventKind::SessionSourceStart,
                    PrimaryEventKind::Ready => EventKind::SessionReady,
                    PrimaryEventKind::Stop => EventKind::SessionStop,
                    PrimaryEventKind::SourceExit => EventKind::SessionSourceExit,
                    PrimaryEventKind::PrimaryRequest => EventKind::PrimaryRequest,
                    PrimaryEventKind::PrimaryResponseHeaders => EventKind::PrimaryResponseHeaders,
                    PrimaryEventKind::PrimaryResponsePart => EventKind::PrimaryResponsePart,
                    PrimaryEventKind::PrimaryResponseTrailers => EventKind::PrimaryResponseTrailers,
                    PrimaryEventKind::PrimaryResponseEnd => EventKind::PrimaryResponseEnd,
                    PrimaryEventKind::PrimaryCancel => EventKind::PrimaryCancel,
                },
            })))
        }
        Ok(SessionTimelineEvent::Dependency(event)) => {
            let sequence = event.event.dependency_sequence()?;
            if sequence == event.sequence {
                unseen_preludes.remove(&sequence);
            }
            references
                .contains(&sequence)
                .then_some(Ok(SessionPlanEvent::Dependency(event)))
        }
    });
    let plan = SequencePlan::compile_session(events)?;
    ensure!(
        plan.dependency_count() == references.len() && unseen_preludes.is_empty(),
        "session dependency inventory is missing a Source event trace"
    );
    Ok(plan)
}

pub(super) async fn control<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: Arc<Mutex<RuntimeState<P>>>,
) -> Value {
    match control_result(request, &state).await {
        Ok(()) => state
            .lock()
            .await
            .session_events
            .as_ref()
            .expect("session mode")
            .response(None),
        Err(error) => {
            let error = error.to_string();
            let state = state.lock().await;
            state.session_events.as_ref().map_or_else(
                || serde_json::json!({"ok": false, "error": error}),
                |session| session.response(Some(&error)),
            )
        }
    }
}

async fn control_result<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    state: &Arc<Mutex<RuntimeState<P>>>,
) -> Result<()> {
    let mut locked = state.lock().await;
    ensure!(locked.finalized_at.is_none(), "Replay is already finalized");
    let session = locked
        .session_events
        .as_mut()
        .context("session event Replay is not enabled")?;
    if request.command == "session_status" {
        return Ok(());
    }
    let sequence = match request.parameters.get("sequence") {
        Some(traffic_value::Value::Number(traffic_value::Number::Unsigned(sequence))) => *sequence,
        _ => anyhow::bail!("session event control requires a sequence"),
    };
    if request.command == "session_fail" {
        let reason = request
            .parameters
            .get("reason")
            .and_then(traffic_value::Value::as_str)
            .filter(|reason| !reason.is_empty())
            .context("session failure requires a reason")?;
        session.fail(Some(sequence), None, reason);
        return Ok(());
    }
    ensure!(
        session.runtime.driver_event(sequence).is_some(),
        "Source sequence {sequence} is not a driver event"
    );
    if request.command == "session_commit" {
        if let Err(error) = session.runtime.commit_driver(sequence) {
            session.fail(Some(sequence), None, &error.to_string());
        }
        return Ok(());
    }
    let runtime = session.runtime.clone();
    let timeout = session.no_progress_timeout;
    drop(locked);
    let mut changed = runtime.subscribe();
    let mut previous = None;
    let mut deadline = Instant::now() + timeout;
    loop {
        let progress = runtime.progress();
        if progress.failed {
            return Ok(());
        }
        if progress
            .expected
            .is_some_and(|event| event.sequence == sequence)
            && !runtime.event_is_gated(sequence)
        {
            if let Some(due) = runtime
                .driver_due(sequence)
                .filter(|due| *due > Instant::now())
            {
                tokio::select! {
                    _ = tokio::time::sleep_until(due) => {},
                    result = changed.changed() => { result.context("session Replay sequence closed")?; },
                }
                continue;
            }
            return Ok(());
        }
        if progress
            .expected
            .is_none_or(|event| event.sequence > sequence)
        {
            anyhow::bail!("Source driver sequence {sequence} has already been passed");
        }
        if progress.last_sequence != previous {
            previous = progress.last_sequence;
            deadline = Instant::now() + timeout;
        }
        if tokio::time::timeout_at(deadline, changed.changed())
            .await
            .is_err()
        {
            let mut state = state.lock().await;
            if runtime.progress().last_sequence == previous {
                state.session_events.as_mut().expect("session mode").fail(
                    Some(sequence),
                    None,
                    "next recorded event did not occur before the Replay progress deadline",
                );
                return Ok(());
            }
        }
    }
}
