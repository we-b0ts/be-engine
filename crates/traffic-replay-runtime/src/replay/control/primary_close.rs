//! One Source timeline for an independent HTTP client close and dependency streams.
use super::*;
use futures_util::future::BoxFuture;
use std::collections::BTreeMap;
use std::sync::Mutex as SyncMutex;
use tokio::sync::watch;
use tokio::time::Instant as MonoInstant;
use traffic_protocol::io::delivery::{DeliveryProgress, PrefixDelivery};

mod source;
use crate::replay::protocol_runtime::primary_close::SourceStream;

#[derive(Debug)]
pub(crate) struct Timeline {
    case: String,
    epoch: DateTime<Utc>,
    admission_epoch: u64,
    started: MonoInstant,
    plan: source::Plan,
    prefixes: SyncMutex<BTreeMap<ProtocolExchange, Arc<PrefixDelivery>>>,
    primary_close: SyncMutex<Option<std::time::Instant>>,
    // 0: waiting, 1: actual primary cancellation sent, 2: abandoned Case.
    stage: watch::Sender<u8>,
}

impl Timeline {
    #[allow(dead_code)]
    pub(crate) fn cancellation_diagnosis(
        &self,
        transport: impl FnOnce(std::time::Instant) -> Value,
    ) -> Value {
        serde_json::json!({"stage":*self.stage.borrow(), "prefix_ready":self.ready(),
            "actual_primary_close_ms":self.primary_close.lock().expect("primary close clock poisoned").map(|at| at.saturating_duration_since(self.started.into_std()).as_millis()),
            "transport":transport(self.started.into_std())})
    }
    #[allow(dead_code)]
    pub(crate) fn permits_cancellation(
        &self,
        reference: ProtocolExchange,
        at: std::time::Instant,
    ) -> bool {
        *self.stage.borrow() == 1
            && self.ready()
            && self
                .plan
                .streams
                .get(&reference)
                .is_some_and(|s| s.end_after_close && s.prefix_required)
            && self
                .primary_close
                .lock()
                .expect("primary close clock poisoned")
                .is_some_and(|close| at >= close)
    }

    #[allow(dead_code)]
    pub(crate) async fn wait_closed(&self) {
        let mut stage = self.stage.subscribe();
        while *stage.borrow_and_update() == 0 {
            if stage.changed().await.is_err() {
                break;
            }
        }
    }
    pub(crate) fn abort(&self) {
        self.stage.send_replace(2);
    }

    fn ready(&self) -> bool {
        self.started.elapsed() >= Duration::from_millis(self.plan.close_ms)
            && self.plan.streams.iter().all(|(index, stream)| {
                !stream.prefix_required
                    || self
                        .prefixes
                        .lock()
                        .expect("primary close prefixes poisoned")
                        .get(index)
                        .is_some_and(|prefix| prefix.is_complete())
            })
    }

    #[allow(dead_code)]
    pub(crate) fn bind(
        self: &Arc<Self>,
        reference: ProtocolExchange,
        progress: DeliveryProgress,
    ) -> Result<Option<BoundStream>> {
        let Some(stream) = self.plan.streams.get(&reference) else {
            return Ok(None);
        };
        let prefix = Arc::new(PrefixDelivery::new(progress));
        {
            let mut prefixes = self
                .prefixes
                .lock()
                .expect("primary close prefixes poisoned");
            let std::collections::btree_map::Entry::Vacant(entry) = prefixes.entry(reference)
            else {
                anyhow::bail!("primary close timeline stream was bound twice");
            };
            entry.insert(prefix.clone());
        }
        let mut stage = self.stage.subscribe();
        let released = Box::pin(async move {
            loop {
                match *stage.borrow_and_update() {
                    1 => return Ok(()),
                    2 => anyhow::bail!("primary close timeline Case was abandoned"),
                    _ => {}
                }
                stage
                    .changed()
                    .await
                    .context("primary close timeline ended")?;
            }
        });
        Ok(Some(BoundStream {
            timeline: self.clone(),
            started: self.started,
            schedule: stream.clone(),
            prefix,
            released: SyncMutex::new(released),
            release_result: None,
        }))
    }
}

#[allow(dead_code)]
pub(crate) struct BoundStream {
    pub timeline: Arc<Timeline>,
    pub started: MonoInstant,
    pub schedule: source::StreamSchedule,
    pub prefix: Arc<PrefixDelivery>,
    released: SyncMutex<BoxFuture<'static, Result<()>>>,
    release_result: Option<std::result::Result<(), String>>,
}

impl BoundStream {
    #[allow(dead_code)]
    pub(crate) fn poll_release(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        if self.release_result.is_none() {
            match self
                .released
                .lock()
                .expect("primary close waiter poisoned")
                .as_mut()
                .poll(cx)
            {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(result) => {
                    self.release_result = Some(result.map_err(|error| format!("{error:#}")))
                }
            }
        }
        std::task::Poll::Ready(
            self.release_result
                .as_ref()
                .unwrap()
                .clone()
                .map_err(anyhow::Error::msg),
        )
    }
    #[allow(dead_code)]
    pub(crate) async fn wait_release(&mut self) -> Result<()> {
        futures_util::future::poll_fn(|cx| self.poll_release(cx)).await
    }
}

pub(super) async fn accept<P: ReplayProtocolSet>(
    request: &ReplayControlRequest,
    shared: &Arc<Mutex<RuntimeState<P>>>,
) -> Value {
    let result = async {
        let case = request
            .case_id
            .as_deref()
            .context("primary close timing requires case_id")?;
        if request.command == "http_input_timing_begin" {
            let (recording, streams, cap, admission_epoch) = {
                let state = shared.lock().await;
                ensure_live(&state, case)?;
                if state.stream_timing != Some(crate::replay::ReplayStreamTiming::Fast) {
                    return Ok(serde_json::json!({"ok":true,"enabled":false}));
                }
                let streams = P::primary_streams(&state, case)?;
                (
                    state
                        .cases
                        .get(case)
                        .context("primary close timing Case absent")?
                        .clone(),
                    streams,
                    state.stream_interval_cap_ms,
                    state.admission_epoch,
                )
            };
            let plan = tokio::task::spawn_blocking(move || {
                source::prepare(P::primary_close_input(&recording)?, streams, cap)
            })
            .await??;
            let Some(plan) = plan else {
                return Ok(serde_json::json!({"ok":true,"enabled":false}));
            };
            let recording = shared
                .lock()
                .await
                .cases
                .get(case)
                .context("primary close timing Case absent")?
                .clone();
            let source_close_ms = plan.source_close_ms;
            let caches = tokio::task::spawn_blocking(move || {
                P::prepare_primary_close(&recording, source_close_ms)
            })
            .await??;
            let mut state = shared.lock().await;
            ensure_live(&state, case)?;
            ensure!(
                state.admission_epoch == admission_epoch && state.primary_close_timing.is_none(),
                "primary close timing Case admission changed"
            );
            let epoch = Utc::now();
            state.protocols.install_primary_close(case, caches)?;
            tracing::info!(
                case_id = case,
                source_close_ms = plan.source_close_ms,
                replay_close_ms = plan.close_ms,
                streams = plan.streams.len(),
                "prepared shared primary close timeline"
            );
            state.primary_close_timing = Some(Arc::new(Timeline {
                case: case.into(),
                epoch,
                admission_epoch,
                started: MonoInstant::now(),
                plan,
                prefixes: SyncMutex::default(),
                primary_close: SyncMutex::new(None),
                stage: watch::channel(0).0,
            }));
            return Ok(serde_json::json!({"ok":true,"enabled":true,"epoch":epoch}));
        }
        let query = request
            .input_timing
            .as_ref()
            .context("primary close timing metadata absent")?;
        let mut state = shared.lock().await;
        ensure_live(&state, case)?;
        let live = state
            .primary_close_timing
            .as_ref()
            .context("primary close timing not admitted")?;
        ensure!(
            live.case == case
                && live.epoch == query.epoch
                && live.admission_epoch == state.admission_epoch
                && query.sequence == 1
                && query.completed.is_empty(),
            "primary close timing identity changed"
        );
        ensure!(
            *live.stage.borrow() != 2,
            "primary close timing Case abandoned"
        );
        let ready = live.ready();
        if request.command == "http_input_timing_closed" {
            ensure!(
                ready,
                "primary close preceded its delivered Source input prefix"
            );
            let closed_at = query
                .closed_at
                .context("actual primary close clock missing")?;
            let lag = (Utc::now() - closed_at)
                .to_std()
                .context("primary close clock is in the future")?;
            let at = std::time::Instant::now()
                .checked_sub(lag)
                .context("invalid primary close clock")?;
            ensure!(
                closed_at >= live.epoch
                    && at >= (live.started + Duration::from_millis(live.plan.close_ms)).into_std(),
                "primary close clock preceded its scheduled input"
            );
            let mut primary = live
                .primary_close
                .lock()
                .expect("primary close clock poisoned");
            ensure!(primary.is_none(), "primary close was acknowledged twice");
            *primary = Some(at);
            drop(primary);
            live.stage.send_replace(1);
            state.protocols.primary_closed(case);
        }
        Ok(serde_json::json!({"ok":true,"ready":ready,"wait_ms":5,"advance":{"removed_ms":0}}))
    }
    .await;
    result.unwrap_or_else(
        |error: anyhow::Error| serde_json::json!({"ok":false,"error":format!("{error:#}")}),
    )
}

fn ensure_live<P: ReplayProtocolSet>(state: &RuntimeState<P>, case: &str) -> Result<()> {
    ensure!(
        state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(),
        "primary close timing requires the active unfinished Case"
    );
    Ok(())
}
