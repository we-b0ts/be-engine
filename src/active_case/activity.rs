use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;
use tokio::time::{Instant as TokioInstant, sleep_until};

#[derive(Debug)]
pub(super) struct DependencyActivity {
    state: Mutex<DependencyActivityState>,
    changed: Notify,
}

#[derive(Debug)]
struct DependencyActivityState {
    in_flight: usize,
    last_activity: Instant,
    request_generation: u64,
}

pub(super) struct DependencyReservation {
    activity: Arc<DependencyActivity>,
}

impl DependencyReservation {
    pub(super) fn touch(&self) {
        self.activity.touch();
    }
}

impl Default for DependencyActivity {
    fn default() -> Self {
        Self {
            state: Mutex::new(DependencyActivityState {
                in_flight: 0,
                last_activity: Instant::now(),
                request_generation: 0,
            }),
            changed: Notify::new(),
        }
    }
}

impl DependencyActivity {
    pub(super) fn touch(&self) {
        self.state
            .lock()
            .expect("dependency activity poisoned")
            .last_activity = Instant::now();
        self.changed.notify_one();
    }

    pub(super) fn snapshot(&self) -> (usize, Instant) {
        let state = self.state.lock().expect("dependency activity poisoned");
        (state.in_flight, state.last_activity)
    }

    pub(super) fn request_snapshot(&self) -> (usize, u64) {
        let state = self.state.lock().expect("dependency activity poisoned");
        (state.in_flight, state.request_generation)
    }

    pub(super) async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Count only a physical request start. Writer clones and protocol frames
    /// retain the existing activity clock without creating another request.
    pub(super) fn reserve_request(self: &Arc<Self>) -> DependencyReservation {
        {
            let mut state = self.state.lock().expect("dependency activity poisoned");
            state.in_flight += 1;
            state.last_activity = Instant::now();
            state.request_generation = state
                .request_generation
                .checked_add(1)
                .expect("dependency request generation overflow");
        }
        self.changed.notify_one();
        DependencyReservation {
            activity: self.clone(),
        }
    }
    pub(super) fn reserve(self: &Arc<Self>) -> DependencyReservation {
        {
            let mut state = self.state.lock().expect("dependency activity poisoned");
            state.in_flight += 1;
            state.last_activity = Instant::now();
        }
        self.changed.notify_one();
        DependencyReservation {
            activity: self.clone(),
        }
    }

    pub(super) async fn wait_until_idle(&self) {
        loop {
            let changed = self.changed.notified();
            if self
                .state
                .lock()
                .expect("dependency activity poisoned")
                .in_flight
                == 0
            {
                return;
            }
            changed.await;
        }
    }

    pub(super) async fn wait_until_idle_until(&self, deadline: Instant) -> bool {
        loop {
            let changed = self.changed.notified();
            let in_flight = self
                .state
                .lock()
                .expect("dependency activity poisoned")
                .in_flight;
            if in_flight == 0 {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            tokio::select! {
                _ = sleep_until(TokioInstant::from_std(deadline)) => {}
                _ = changed => {}
            }
        }
    }

    pub(super) fn is_quiet(&self, quiet: std::time::Duration) -> bool {
        let state = self.state.lock().expect("dependency activity poisoned");
        state.in_flight == 0 && state.last_activity.elapsed() >= quiet
    }

    pub(super) async fn wait_until_quiet(&self, quiet: std::time::Duration) {
        loop {
            let changed = self.changed.notified();
            let (in_flight, last_activity) = self.snapshot();
            let quiet_at = last_activity + quiet;
            if in_flight == 0 && Instant::now() >= quiet_at {
                return;
            }
            if in_flight == 0 {
                tokio::select! {
                    _ = sleep_until(TokioInstant::from_std(quiet_at)) => {},
                    _ = changed => {},
                }
            } else {
                changed.await;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn set_last_activity(&self, at: Instant) {
        self.state
            .lock()
            .expect("dependency activity poisoned")
            .last_activity = at;
        self.changed.notify_one();
    }

    pub(super) async fn wait_until_quiet_until(
        &self,
        quiet: std::time::Duration,
        deadline: Instant,
    ) -> bool {
        loop {
            let changed = self.changed.notified();
            let (in_flight, quiet_at) = {
                let state = self.state.lock().expect("dependency activity poisoned");
                (state.in_flight, state.last_activity + quiet)
            };
            let now = Instant::now();
            if in_flight == 0 && now >= quiet_at {
                return quiet_at <= deadline;
            }
            if now >= deadline {
                return false;
            }
            let wake_at = if in_flight == 0 {
                quiet_at.min(deadline)
            } else {
                deadline
            };
            tokio::select! {
                _ = sleep_until(TokioInstant::from_std(wake_at)) => {}
                _ = changed => {}
            }
        }
    }
}

impl Clone for DependencyReservation {
    fn clone(&self) -> Self {
        self.activity.reserve()
    }
}

impl std::fmt::Debug for DependencyReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DependencyReservation").finish()
    }
}

impl Drop for DependencyReservation {
    fn drop(&mut self) {
        {
            let mut state = self
                .activity
                .state
                .lock()
                .expect("dependency activity poisoned");
            state.in_flight = state
                .in_flight
                .checked_sub(1)
                .expect("dependency reservation underflow");
            state.last_activity = Instant::now();
        }
        self.activity.changed.notify_one();
    }
}
