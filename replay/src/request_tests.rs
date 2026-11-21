use super::*;
use tokio::sync::oneshot;

#[derive(Default)]
struct State {
    lifecycle: Lifecycle,
    epoch: u64,
    ready: bool,
    finalized: bool,
    observations: usize,
    commits: usize,
    rejections: usize,
}

impl ExecutionState for State {
    type Observation = u64;

    fn is_finalized(&self) -> bool {
        self.finalized
    }

    fn cancel_reason(&self, observation: &u64) -> Option<&'static str> {
        (self.epoch != *observation).then_some("request scope changed")
    }

    fn sequence_wait(&self, _bytes: usize) -> Option<RequestWait> {
        None
    }

    fn record_missing(&mut self, _observation: &u64, _waiter: &RequestWait) {
        panic!("this fixture has no Source sequence")
    }
}

struct Request {
    observed: Option<oneshot::Sender<()>>,
}

impl RequestAdapter<State> for Request {
    type Matched = u64;
    type Error = &'static str;

    fn observe_once(&mut self, state: &mut State) -> u64 {
        state.observations += 1;
        if let Some(observed) = self.observed.take() {
            let _ = observed.send(());
        }
        state.epoch
    }

    fn try_select(&mut self, state: &mut State, observation: &u64) -> Result<u64, &'static str> {
        state.ready.then_some(*observation).ok_or("waiting")
    }

    fn wait_dependency<'a>(
        &self,
        state: &'a State,
        _observation: &u64,
        _error: &&'static str,
    ) -> Option<WaitDependency<'a>> {
        (!state.ready).then(|| WaitDependency::changed(&state.lifecycle))
    }

    fn interrupted(&self, reason: &'static str) -> &'static str {
        reason
    }

    fn on_selected(
        &mut self,
        state: &mut State,
        _observation: &u64,
        _matched: &mut u64,
    ) -> Result<(), &'static str> {
        state.commits += 1;
        Ok(())
    }

    fn on_rejected(&mut self, state: &mut State, _observation: &u64, _error: &&'static str) {
        state.rejections += 1;
    }
}

#[tokio::test]
async fn a_new_context_reuses_observation_wait_and_commit_without_native_types() {
    let state = Arc::new(Mutex::new(State::default()));
    let (observed, observing) = oneshot::channel();
    let shared = state.clone();
    let execution = tokio::spawn(async move {
        execute(
            &shared,
            &mut Request {
                observed: Some(observed),
            },
            Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
    });
    observing.await.unwrap();
    {
        let mut state = state.lock().await;
        state.ready = true;
        state.lifecycle.notify_waiters();
    }
    assert_eq!(execution.await.unwrap(), Ok(0));
    let state = state.lock().await;
    assert_eq!(state.observations, 1);
    assert_eq!(state.commits, 1);
    assert_eq!(state.rejections, 0);
}

#[tokio::test]
async fn cancellation_and_finalization_retain_the_framework_boundary() {
    let state = Arc::new(Mutex::new(State::default()));
    let (observed, observing) = oneshot::channel();
    let shared = state.clone();
    let execution = tokio::spawn(async move {
        execute(
            &shared,
            &mut Request {
                observed: Some(observed),
            },
            Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
    });
    observing.await.unwrap();
    {
        let mut state = state.lock().await;
        state.epoch += 1;
        state.ready = true;
        state.lifecycle.notify_waiters();
    }
    assert_eq!(execution.await.unwrap(), Err("request scope changed"));
    {
        let mut state = state.lock().await;
        assert_eq!(state.observations, 1);
        assert_eq!(state.commits, 0);
        assert_eq!(state.rejections, 1);
        state.finalized = true;
    }
    let result = execute(
        &state,
        &mut Request { observed: None },
        Instant::now() + std::time::Duration::from_secs(2),
    )
    .await;
    assert_eq!(result, Err("Replay session is finalized"));
    assert_eq!(state.lock().await.observations, 1);
}
