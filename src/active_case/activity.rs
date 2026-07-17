use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
}

pub(super) struct DependencyReservation {
    activity: Arc<DependencyActivity>,
}

impl Default for DependencyActivity {
    fn default() -> Self {
        Self {
            state: Mutex::new(DependencyActivityState {
                in_flight: 0,
                last_activity: Instant::now(),
            }),
            changed: Notify::new(),
        }
    }
}

impl DependencyActivity {
    pub(super) fn reserve(self: &Arc<Self>) -> DependencyReservation {
        {
            let mut state = self.state.lock().expect("dependency activity poisoned");
            state.in_flight += 1;
            state.last_activity = Instant::now();
        }
        self.changed.notify_waiters();
        DependencyReservation {
            activity: self.clone(),
        }
    }

    pub(super) fn touch(&self) {
        self.state
            .lock()
            .expect("dependency activity poisoned")
            .last_activity = Instant::now();
        self.changed.notify_waiters();
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

    pub(super) async fn wait_until_quiet(&self, quiet_period: Duration, deadline: Instant) -> bool {
        loop {
            let changed = self.changed.notified();
            let (in_flight, last_activity) = {
                let state = self.state.lock().expect("dependency activity poisoned");
                (state.in_flight, state.last_activity)
            };
            let now = Instant::now();
            if in_flight == 0 && now.saturating_duration_since(last_activity) >= quiet_period {
                return true;
            }
            if now >= deadline {
                return false;
            }
            let next_check = if in_flight == 0 {
                deadline.min(last_activity + quiet_period)
            } else {
                deadline
            };
            tokio::select! {
                _ = sleep_until(TokioInstant::from_std(next_check)) => {}
                _ = changed => {}
            }
        }
    }

    pub(super) fn is_quiet_for(&self, quiet_period: Duration) -> bool {
        let state = self.state.lock().expect("dependency activity poisoned");
        state.in_flight == 0 && state.last_activity.elapsed() >= quiet_period
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
        self.activity.changed.notify_waiters();
    }
}
