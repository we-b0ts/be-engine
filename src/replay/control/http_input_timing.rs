//! One Source timeline for an independent HTTP client close and dependency streams.
use super::*;
use crate::http::termination::{DeliveryProgress, PrefixDelivery};
use crate::interaction::replay::timing::InputTiming;
use futures_util::future::BoxFuture;
use std::collections::BTreeMap;
use std::sync::Mutex as SyncMutex;
use tokio::sync::watch;
use tokio::time::Instant as MonoInstant;

mod client;
mod source;
pub(crate) use client::connect;
pub(in crate::replay) use source::SourceStream;

#[derive(Debug)]
pub(in crate::replay) struct Timeline {
    case: String,
    epoch: DateTime<Utc>,
    admission_epoch: u64,
    started: MonoInstant,
    plan: source::Plan,
    prefixes: SyncMutex<BTreeMap<usize, Arc<PrefixDelivery>>>,
    primary_close: SyncMutex<Option<std::time::Instant>>,
    // 0: waiting, 1: actual primary cancellation sent, 2: abandoned Case.
    stage: watch::Sender<u8>,
}

impl Timeline {
    pub(in crate::replay) fn permits_cancellation(
        &self,
        index: usize,
        at: std::time::Instant,
    ) -> bool {
        *self.stage.borrow() == 1
            && self.ready()
            && self
                .plan
                .streams
                .get(&index)
                .is_some_and(|s| s.end_after_close && s.prefix_required)
            && self
                .primary_close
                .lock()
                .expect("HTTP close clock poisoned")
                .is_some_and(|close| at >= close)
    }

    pub(in crate::replay) async fn wait_closed(&self) {
        let mut stage = self.stage.subscribe();
        while *stage.borrow_and_update() == 0 {
            if stage.changed().await.is_err() {
                break;
            }
        }
    }
    pub(in crate::replay) fn abort(&self) {
        self.stage.send_replace(2);
    }

    fn ready(&self) -> bool {
        self.started.elapsed() >= Duration::from_millis(self.plan.close_ms)
            && self.plan.streams.iter().all(|(index, stream)| {
                !stream.prefix_required
                    || self
                        .prefixes
                        .lock()
                        .expect("HTTP input prefixes poisoned")
                        .get(index)
                        .is_some_and(|prefix| prefix.is_complete())
            })
    }

    pub(in crate::replay) fn bind(
        self: &Arc<Self>,
        index: usize,
        progress: DeliveryProgress,
    ) -> Result<Option<BoundStream>> {
        let Some(stream) = self.plan.streams.get(&index) else {
            return Ok(None);
        };
        let prefix = Arc::new(PrefixDelivery::new(progress));
        ensure!(
            self.prefixes
                .lock()
                .expect("HTTP input prefixes poisoned")
                .insert(index, prefix.clone())
                .is_none(),
            "HTTP input timeline stream was bound twice"
        );
        let mut stage = self.stage.subscribe();
        let released = Box::pin(async move {
            loop {
                match *stage.borrow_and_update() {
                    1 => return Ok(()),
                    2 => anyhow::bail!("HTTP input timeline Case was abandoned"),
                    _ => {}
                }
                stage.changed().await.context("HTTP input timeline ended")?;
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

pub(in crate::replay) struct BoundStream {
    pub timeline: Arc<Timeline>,
    pub started: MonoInstant,
    pub schedule: source::StreamSchedule,
    pub prefix: Arc<PrefixDelivery>,
    released: SyncMutex<BoxFuture<'static, Result<()>>>,
    release_result: Option<std::result::Result<(), String>>,
}

impl BoundStream {
    pub(in crate::replay) fn poll_release(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        if self.release_result.is_none() {
            match self
                .released
                .lock()
                .expect("HTTP close waiter poisoned")
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
    pub(in crate::replay) async fn wait_release(&mut self) -> Result<()> {
        futures_util::future::poll_fn(|cx| self.poll_release(cx)).await
    }
}

pub(super) async fn accept(
    request: &ReplayControlRequest,
    shared: &Arc<Mutex<ReplayState>>,
) -> Value {
    let result = async {
        let case = request
            .case_id
            .as_deref()
            .context("HTTP timing requires case_id")?;
        if request.command == "http_input_timing_begin" {
            let (recording, streams, cap, admission_epoch) = {
                let state = shared.lock().await;
                ensure_live(&state, case)?;
                if state.stream_timing != Some(crate::replay::ReplayStreamTiming::Fast) {
                    return Ok(serde_json::json!({"ok":true,"enabled":false}));
                }
                let streams = crate::replay::http::input_timing::source_streams(&state, case)?;
                (
                    state
                        .cases
                        .get(case)
                        .context("HTTP timing Case absent")?
                        .clone(),
                    streams,
                    state.stream_interval_cap_ms,
                    state.admission_epoch,
                )
            };
            let plan =
                tokio::task::spawn_blocking(move || source::prepare(&recording, streams, cap))
                    .await??;
            let Some(plan) = plan else {
                return Ok(serde_json::json!({"ok":true,"enabled":false}));
            };
            let recording = shared
                .lock()
                .await
                .cases
                .get(case)
                .context("HTTP timing Case absent")?
                .clone();
            let source_close_ms = plan.source_close_ms;
            let caches = tokio::task::spawn_blocking(move || {
                crate::replay::redis::append::cancelled::load(&recording, source_close_ms)
            })
            .await??;
            let mut state = shared.lock().await;
            ensure_live(&state, case)?;
            ensure!(
                state.admission_epoch == admission_epoch && state.http_input_timing.is_none(),
                "HTTP timing Case admission changed"
            );
            let epoch = Utc::now();
            state.redis.prepare_cancelled_caches(case, caches)?;
            tracing::info!(
                case_id = case,
                source_close_ms = plan.source_close_ms,
                replay_close_ms = plan.close_ms,
                streams = plan.streams.len(),
                "prepared shared HTTP input timeline"
            );
            state.http_input_timing = Some(Arc::new(Timeline {
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
            .context("HTTP timing metadata absent")?;
        let mut state = shared.lock().await;
        ensure_live(&state, case)?;
        let live = state
            .http_input_timing
            .as_ref()
            .context("HTTP timing not admitted")?;
        ensure!(
            live.case == case
                && live.epoch == query.epoch
                && live.admission_epoch == state.admission_epoch
                && query.sequence == 1
                && query.completed.is_empty(),
            "HTTP timing identity changed"
        );
        ensure!(*live.stage.borrow() != 2, "HTTP timing Case abandoned");
        let ready = live.ready();
        if request.command == "http_input_timing_closed" {
            ensure!(
                ready,
                "primary close preceded its delivered Source input prefix"
            );
            let closed_at = query
                .closed_at
                .context("actual HTTP primary close clock missing")?;
            let lag = (Utc::now() - closed_at)
                .to_std()
                .context("HTTP close clock is in the future")?;
            let at = std::time::Instant::now()
                .checked_sub(lag)
                .context("invalid HTTP close clock")?;
            ensure!(
                closed_at >= live.epoch
                    && at >= (live.started + Duration::from_millis(live.plan.close_ms)).into_std(),
                "HTTP close clock preceded its scheduled input"
            );
            let mut primary = live
                .primary_close
                .lock()
                .expect("HTTP close clock poisoned");
            ensure!(
                primary.is_none(),
                "HTTP primary close was acknowledged twice"
            );
            *primary = Some(at);
            drop(primary);
            live.stage.send_replace(1);
            state.redis.confirm_cancelled_caches(case);
        }
        Ok(serde_json::json!({"ok":true,"ready":ready,"wait_ms":5,"advance":{"removed_ms":0}}))
    }
    .await;
    result.unwrap_or_else(
        |error: anyhow::Error| serde_json::json!({"ok":false,"error":format!("{error:#}")}),
    )
}

fn ensure_live(state: &ReplayState, case: &str) -> Result<()> {
    ensure!(
        state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(),
        "HTTP input timing requires the active unfinished Case"
    );
    Ok(())
}
