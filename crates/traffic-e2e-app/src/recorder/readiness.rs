use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostReadyWaitOutcome {
    QuietPeriodElapsed,
    MaximumWaitElapsed,
}

#[derive(Debug)]
pub(crate) struct CacheActivity {
    last_request_at: watch::Sender<Option<Instant>>,
}

impl Default for CacheActivity {
    fn default() -> Self {
        let (last_request_at, _) = watch::channel(None);
        Self { last_request_at }
    }
}

impl CacheActivity {
    pub(crate) fn record_request(&self) {
        self.last_request_at.send_replace(Some(Instant::now()));
    }

    pub(crate) async fn wait_for_quiet_period(
        &self,
        ready_at: Instant,
        quiet_period: Duration,
        maximum_wait: Duration,
    ) -> PostReadyWaitOutcome {
        if quiet_period.is_zero() {
            return PostReadyWaitOutcome::QuietPeriodElapsed;
        }
        let maximum_deadline = ready_at + maximum_wait;
        let mut activity = self.last_request_at.subscribe();
        loop {
            let last_request_at = (*activity.borrow_and_update())
                .filter(|observed_at| *observed_at > ready_at)
                .unwrap_or(ready_at);
            let quiet_deadline = last_request_at + quiet_period;
            let deadline = quiet_deadline.min(maximum_deadline);
            if Instant::now() >= deadline {
                return if quiet_deadline <= maximum_deadline {
                    PostReadyWaitOutcome::QuietPeriodElapsed
                } else {
                    PostReadyWaitOutcome::MaximumWaitElapsed
                };
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                changed = activity.changed() => {
                    if changed.is_err() {
                        tokio::time::sleep_until(deadline).await;
                        return if quiet_deadline <= maximum_deadline {
                            PostReadyWaitOutcome::QuietPeriodElapsed
                        } else {
                            PostReadyWaitOutcome::MaximumWaitElapsed
                        };
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redis_request_slides_the_quiet_deadline() {
        let activity = CacheActivity::default();
        let ready_at = Instant::now();
        let wait = activity.wait_for_quiet_period(
            ready_at,
            Duration::from_millis(50),
            Duration::from_millis(500),
        );
        tokio::pin!(wait);
        tokio::time::sleep(Duration::from_millis(30)).await;
        activity.record_request();

        assert_eq!(wait.await, PostReadyWaitOutcome::QuietPeriodElapsed);
        assert!(ready_at.elapsed() >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn continuous_redis_requests_stop_at_the_maximum_wait() {
        let activity = CacheActivity::default();
        let ready_at = Instant::now();
        let wait = activity.wait_for_quiet_period(
            ready_at,
            Duration::from_millis(50),
            Duration::from_millis(90),
        );
        tokio::pin!(wait);
        tokio::time::sleep(Duration::from_millis(30)).await;
        activity.record_request();
        tokio::time::sleep(Duration::from_millis(30)).await;
        activity.record_request();

        assert_eq!(wait.await, PostReadyWaitOutcome::MaximumWaitElapsed);
        assert!(ready_at.elapsed() >= Duration::from_millis(90));
    }
}
