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
    pub(super) fn snapshot(&self) -> (usize, Instant) {
        let state = self.state.lock().expect("dependency activity poisoned");
        (state.in_flight, state.last_activity)
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
