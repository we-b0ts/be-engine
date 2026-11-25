//! Target waits attached to the live recorded event frontier.
mod plan;
mod transport;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tokio::sync::watch;
use tokio::time::Instant;
use traffic_replay::{SequencePlan, SequenceRuntime};

use self::plan::{Anchor, Checkpoint, Plan};
pub(super) use self::transport::Listener;
use self::transport::Registration;

/// Optional timer control for one fast Replay session.
#[derive(Clone, Debug)]
pub struct ReplayTimerConfig {
    pub plan_path: PathBuf,
    pub socket_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum TimerEventKind {
    #[serde(rename = "timer_start")]
    Start,
    #[serde(rename = "timer_wake")]
    Wake,
    #[serde(rename = "timer_end")]
    End,
    #[serde(rename = "timer_cancelled")]
    Cancelled,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TimerEvent {
    case_id: String,
    admission_epoch: u64,
    site: String,
    stream: String,
    occurrence: u64,
    #[serde(flatten)]
    anchor: Anchor,
    consumed_through: u64,
    offset_micros: u64,
    kind: TimerEventKind,
}

#[derive(Debug, Default)]
pub(crate) struct Timers {
    plan: Plan,
    active: Option<Active>,
    events: Vec<TimerEvent>,
    changed: watch::Sender<()>,
}

#[derive(Debug)]
struct Active {
    case_id: String,
    started: Instant,
    stages: BTreeMap<u64, (u64, TimerEventKind)>,
}

struct Lease {
    case_id: String,
    epoch: u64,
    step: Checkpoint,
    sequence: Arc<SequenceRuntime>,
    scope_changed: watch::Receiver<()>,
}

impl Timers {
    pub(super) async fn load(config: &ReplayTimerConfig) -> Result<Self> {
        Ok(Self {
            plan: Plan::load(&config.plan_path).await?,
            ..Self::default()
        })
    }

    pub(super) fn validate_case(&self, case: &str, plan: Option<&SequencePlan>) -> Result<()> {
        self.plan.validate_case(case, plan)
    }

    pub(super) fn validate_session(&self, scope: &str, plan: &SequencePlan) -> Result<()> {
        self.plan.validate_session(scope, plan)
    }

    pub(super) fn stream_session_anchors(
        &self,
        scope: &str,
    ) -> Result<BTreeMap<u64, traffic_replay::EventKind>> {
        self.plan.stream_session_anchors(scope)
    }

    pub(super) fn activate(&mut self, case: Option<&str>) {
        self.cancel_pending();
        self.active = case
            .filter(|case| !self.plan.checkpoints(case).is_empty())
            .map(|case| Active {
                case_id: case.to_owned(),
                started: Instant::now(),
                stages: BTreeMap::new(),
            });
        self.changed.send_replace(());
    }

    pub(super) fn epoch_changed(&mut self) {
        self.cancel_pending();
        self.changed.send_replace(());
    }

    fn cancel_pending(&mut self) {
        let Some(active) = &mut self.active else {
            return;
        };
        let elapsed = offset_micros(active.started);
        for step in self.plan.checkpoints(&active.case_id) {
            let Some((epoch, kind)) = active.stages.get_mut(&step.anchor.sequence()) else {
                continue;
            };
            if matches!(kind, TimerEventKind::Start | TimerEventKind::Wake) {
                *kind = TimerEventKind::Cancelled;
                self.events.push(TimerEvent::new(
                    &active.case_id,
                    *epoch,
                    step,
                    elapsed,
                    *kind,
                ));
            }
        }
    }

    pub(super) fn event_gates<'a>(&'a self, case: &str) -> impl Iterator<Item = u64> + 'a {
        self.plan
            .checkpoints(case)
            .iter()
            .map(|step| step.anchor.sequence())
    }

    pub(super) fn events(&self) -> &[TimerEvent] {
        &self.events
    }

    fn register(
        &mut self,
        registration: &Registration,
        epoch: u64,
        sequence: Option<Arc<SequenceRuntime>>,
    ) -> Result<Option<Lease>> {
        let Some(step) = self
            .plan
            .checkpoints(&registration.case_id)
            .iter()
            .find(|step| {
                step.site == registration.site
                    && step.stream == registration.stream
                    && step.occurrence == registration.occurrence
            })
        else {
            return Ok(None);
        };
        ensure!(
            registration.consumed_through == step.consumed_through,
            "Target timer registered at a different input position"
        );
        let lease = Lease {
            case_id: registration.case_id.clone(),
            epoch,
            step: step.clone(),
            sequence: sequence.context("Replay timer Case has no active dependency sequence")?,
            scope_changed: self.changed.subscribe(),
        };
        let active = self.active_for(&lease)?;
        ensure!(
            active
                .stages
                .get(&lease.step.anchor.sequence())
                .is_none_or(|(old_epoch, kind)| {
                    *old_epoch != epoch && *kind == TimerEventKind::Cancelled
                }),
            "Replay timer occurrence was already registered"
        );
        self.record(&lease, TimerEventKind::Start)?;
        Ok(Some(lease))
    }

    fn active_for(&mut self, lease: &Lease) -> Result<&mut Active> {
        self.active
            .as_mut()
            .filter(|active| active.case_id == lease.case_id)
            .context("Replay timer belongs to an inactive Case")
    }

    fn record(&mut self, lease: &Lease, kind: TimerEventKind) -> Result<()> {
        let active = self.active_for(lease)?;
        active
            .stages
            .insert(lease.step.anchor.sequence(), (lease.epoch, kind));
        let elapsed = offset_micros(active.started);
        self.events.push(TimerEvent::new(
            &lease.case_id,
            lease.epoch,
            &lease.step,
            elapsed,
            kind,
        ));
        Ok(())
    }
}

impl TimerEvent {
    fn new(
        case: &str,
        epoch: u64,
        step: &Checkpoint,
        offset_micros: u64,
        kind: TimerEventKind,
    ) -> Self {
        Self {
            case_id: case.into(),
            admission_epoch: epoch,
            site: step.site.clone(),
            stream: step.stream.clone(),
            occurrence: step.occurrence,
            anchor: step.anchor,
            consumed_through: step.consumed_through,
            offset_micros,
            kind,
        }
    }
}

fn offset_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
}

impl Lease {
    fn at_frontier(&self) -> Result<bool> {
        ensure!(!self.sequence.failed(), "Replay timer sequence was aborted");
        let anchor = self.step.anchor;
        let expected = self
            .sequence
            .expected()
            .context("Replay timer anchor was passed")?;
        ensure!(
            expected.sequence <= anchor.sequence(),
            "Replay timer anchor was passed"
        );
        Ok(expected.sequence == anchor.sequence() && expected.kind == anchor.kind())
    }
}
