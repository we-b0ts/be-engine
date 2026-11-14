//! Exercise the actual common engine with native state/notifications, not a
//! second implementation of its retry loop.
use super::*;
use serde_json::json;
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Default)]
struct Counts {
    observed: usize,
    selected: usize,
    accepted: usize,
    rejected: usize,
    ready: bool,
}
struct Probe {
    counts: Arc<StdMutex<Counts>>,
}
impl DependencyRequestAdapter<ReplayState> for Probe {
    type Matched = RequestAdmission;
    type Error = &'static str;
    fn observe_once(&mut self, state: &mut ReplayState) -> RequestAdmission {
        self.counts.lock().unwrap().observed += 1;
        RequestAdmission::capture(
            state,
            Some(7),
            chrono::DateTime::from_timestamp(41, 0),
            Some(Uuid::from_u128(9)),
            true,
        )
    }
    fn try_select(
        &mut self,
        _state: &mut ReplayState,
        observation: &RequestAdmission,
    ) -> Result<Self::Matched, Self::Error> {
        let mut counts = self.counts.lock().unwrap();
        counts.selected += 1;
        if counts.ready {
            Ok(observation.clone())
        } else {
            Err("native predecessor pending")
        }
    }
    fn wait_dependency<'a>(
        &self,
        state: &'a ReplayState,
        _observation: &RequestAdmission,
        _error: &Self::Error,
    ) -> Option<WaitDependency<'a>> {
        (!self.counts.lock().unwrap().ready)
            .then(|| WaitDependency::changed(&state.protocols.redis.lifecycle))
    }
    fn interrupted(&self, reason: &'static str) -> Self::Error {
        reason
    }
    fn on_selected(
        &mut self,
        _state: &mut ReplayState,
        _observation: &RequestAdmission,
        _matched: &mut Self::Matched,
    ) -> Result<(), Self::Error> {
        self.counts.lock().unwrap().accepted += 1;
        Ok(())
    }
    fn on_rejected(
        &mut self,
        _state: &mut ReplayState,
        _observation: &RequestAdmission,
        _error: &Self::Error,
    ) {
        self.counts.lock().unwrap().rejected += 1;
    }
}

async fn fixture() -> (tempfile::TempDir, crate::replay::ReplayRuntime) {
    super::tests::runtime_with_source(&[], json!({"format":"traffic-policy/v3","rules":[]})).await
}

#[tokio::test]
async fn finalized_engine_rejects_without_observation_selection_or_report_hooks() {
    for already_waiting in [false, true] {
        let (_root, runtime) = fixture().await;
        let counts = Arc::new(StdMutex::new(Counts::default()));
        let mut adapter = Probe {
            counts: counts.clone(),
        };
        if !already_waiting {
            runtime.state.lock().await.finalized_at = Some(chrono::Utc::now());
        }
        let execute = request::execute(
            &runtime.state,
            &mut adapter,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        tokio::pin!(execute);
        if already_waiting {
            tokio::select! {biased; result=&mut execute=>panic!("must wait before finalization: {result:?}"),_=std::future::ready(())=>{}}
            let mut state = runtime.state.lock().await;
            state.finalized_at = Some(chrono::Utc::now());
            state.protocols.redis.lifecycle.notify_waiters();
        }
        assert!(execute.await.unwrap_err().contains("finalized"));
        let seen = counts.lock().unwrap();
        let initial = usize::from(already_waiting);
        assert_eq!(
            (seen.observed, seen.selected, seen.accepted, seen.rejected),
            (initial, initial, 0, 0)
        );
    }
}

#[tokio::test]
async fn no_policy_same_case_control_boundaries_cancel_the_previous_engine_epoch() {
    for boundary in ["begin", "request_begin"] {
        let (_root, runtime) = fixture().await;
        let case = {
            let mut state = runtime.state.lock().await;
            state.replay_policy = None;
            state.active_case_id.clone().unwrap()
        };
        let counts = Arc::new(StdMutex::new(Counts::default()));
        let mut adapter = Probe {
            counts: counts.clone(),
        };
        let execute = request::execute(
            &runtime.state,
            &mut adapter,
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        tokio::pin!(execute);
        tokio::select! {biased; result=&mut execute=>panic!("must wait: {result:?}"),_=std::future::ready(())=>{}}
        let request = serde_json::from_value(json!({"command":boundary,"case_id":case})).unwrap();
        let (response, _) = crate::replay::control::handle_control_request(
            request,
            runtime.state.clone(),
            None,
            None,
        )
        .await;
        assert_eq!(response["ok"], true, "{boundary}: {response}");
        {
            let state = runtime.state.lock().await;
            assert_eq!(state.active_case_id.as_deref(), Some(case.as_str()));
            assert!(state.replay_policy.is_none());
            counts.lock().unwrap().ready = true;
            state.protocols.redis.lifecycle.notify_waiters();
        }
        assert!(execute.await.unwrap_err().contains("stopped"));
        let seen = counts.lock().unwrap();
        assert_eq!(
            (seen.observed, seen.selected, seen.accepted, seen.rejected),
            (1, 1, 0, 1)
        );
    }
}

#[tokio::test]
async fn cancelling_the_real_redis_durable_wait_before_delivery_cancels_its_claim() {
    let event = crate::replay::redis::append::tests::event(1, "GET", &[b"session"], b"$1\r\nx\r\n");
    let (_root, runtime) = super::tests::runtime_with_source(
        &[event],
        json!({"format":"traffic-policy/v3","rules":[]}),
    )
    .await;
    let target = TargetKey {
        host: "redis.test".into(),
        port: 6379,
    };
    let command = RedisCommand {
        name: "GET".into(),
        args: vec![b"session".to_vec()],
    };
    let mut binding = CaseConnectionBinding::default();
    let matched = match_command(
        &runtime.state,
        &target,
        Uuid::new_v4(),
        &mut binding,
        2,
        0,
        None,
        &command,
    )
    .await
    .unwrap();
    let index = matched.index;
    let state_ref = runtime.state.clone();
    // This is the actual driver's first await after admission. Holding state
    // parks await_durable before delivery can create a DeliveryGuard.
    let mut state = runtime.state.lock().await;
    let wait = async move {
        crate::replay::policy::request_contract::hypotheses::await_durable(&state_ref)
            .await
            .unwrap();
        drop(matched);
    };
    let mut wait = Box::pin(wait);
    tokio::select! {biased; ()=&mut wait=>panic!("durable wait must be parked on the real state lock"),_=std::future::ready(())=>{}}
    drop(wait);
    assert_eq!(
        state.protocols.redis.exchange_status(index),
        Some(ReplayExchangeStatus::Failed)
    );
    assert_eq!(state.protocols.redis.lifecycle.cancelled_indices(), [index]);
    assert!(!state.protocols.redis.has_case_in_flight());
    assert!(!state.protocols.redis.has_in_flight());
    assert_eq!(state.protocols.redis.events.matched_count, 0);
    assert_eq!(state.protocols.redis.snapshot().unused_case.len(), 1);
    let redis = &mut state.protocols.redis;
    assert!(
        redis
            .lifecycle
            .synchronize(index, &mut redis.exchanges[index].status)
    );
}

#[tokio::test]
async fn common_engine_ignores_foreign_notifications_and_reuses_the_original_observation() {
    let (_root, runtime) = fixture().await;
    let counts = Arc::new(StdMutex::new(Counts::default()));
    let mut adapter = Probe {
        counts: counts.clone(),
    };
    let execute = request::execute(
        &runtime.state,
        &mut adapter,
        tokio::time::Instant::now() + Duration::from_secs(1),
    );
    tokio::pin!(execute);
    tokio::select! {biased; result=&mut execute=>panic!("must wait: {result:?}"),_=std::future::ready(())=>{}}
    runtime
        .state
        .lock()
        .await
        .protocols
        .redis
        .lifecycle
        .notify_waiters();
    tokio::select! {biased; result=&mut execute=>panic!("foreign completion cannot admit: {result:?}"),_=std::future::ready(())=>{}}
    {
        let seen = counts.lock().unwrap();
        assert_eq!((seen.observed, seen.selected), (1, 1));
    }
    {
        let mut state = runtime.state.lock().await;
        state.protocols.redis.request_event_index = Some(999);
        state.protocols.redis.request_observed_at = chrono::DateTime::from_timestamp(999, 0);
        state.protocols.redis.request_observation_id = Some(Uuid::from_u128(99));
        counts.lock().unwrap().ready = true;
        state.protocols.redis.lifecycle.notify_waiters();
    }
    let observed = execute.await.unwrap();
    assert_eq!(observed.event_index, Some(7));
    assert_eq!(
        observed.observed_at,
        chrono::DateTime::from_timestamp(41, 0)
    );
    assert_eq!(observed.observation_id, Some(Uuid::from_u128(9)));
    assert!(observed.observation_retained);
    let seen = counts.lock().unwrap();
    assert_eq!(
        (seen.observed, seen.selected, seen.accepted, seen.rejected),
        (1, 2, 1, 0)
    );
}

#[tokio::test]
async fn common_engine_case_cancellation_and_deadline_never_reobserve_or_retry_selection() {
    for cancel_case in [true, false] {
        let (_root, runtime) = fixture().await;
        let counts = Arc::new(StdMutex::new(Counts::default()));
        let mut adapter = Probe {
            counts: counts.clone(),
        };
        let deadline = tokio::time::Instant::now()
            + if cancel_case {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            };
        let execute = request::execute(&runtime.state, &mut adapter, deadline);
        tokio::pin!(execute);
        if cancel_case {
            tokio::select! {biased; result=&mut execute=>panic!("must wait: {result:?}"),_=std::future::ready(())=>{}}
            let mut state = runtime.state.lock().await;
            state.active_case_id = Some("another-case".into());
            state.protocols.redis.lifecycle.notify_waiters();
        }
        let reason = execute.await.unwrap_err();
        assert!(reason.contains(if cancel_case { "stopped" } else { "timed out" }));
        let seen = counts.lock().unwrap();
        assert_eq!(
            (seen.observed, seen.selected, seen.accepted, seen.rejected),
            (1, 1, 0, 1)
        );
    }
}
