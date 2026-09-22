use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::{Mutex, Notify};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecordingCompletionReason {
    DurationElapsed,
    InputExhausted,
    PerApiCaseLimitReached,
    FailureLimitReached,
    ShutdownSignal,
}

#[derive(Debug, Clone, Copy)]
struct ApiProgress {
    published: usize,
    limit: usize,
    stopped: bool,
}

#[derive(Debug)]
struct ExplicitApiCaseLimitState {
    apis: BTreeMap<String, ApiProgress>,
    complete: bool,
}

#[derive(Debug)]
struct ExplicitApiCaseLimitInner {
    state: Mutex<ExplicitApiCaseLimitState>,
    completed: Notify,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExplicitApiCaseLimits {
    inner: Option<Arc<ExplicitApiCaseLimitInner>>,
}

impl ExplicitApiCaseLimits {
    pub(crate) fn new(limits: impl IntoIterator<Item = (String, usize)>) -> Self {
        let apis = limits
            .into_iter()
            .map(|(api, limit)| {
                (
                    api,
                    ApiProgress {
                        published: 0,
                        limit,
                        stopped: false,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if apis.is_empty() {
            return Self::default();
        }
        let complete = apis.values().all(|progress| progress.limit == 0);
        Self {
            inner: Some(Arc::new(ExplicitApiCaseLimitInner {
                state: Mutex::new(ExplicitApiCaseLimitState { apis, complete }),
                completed: Notify::new(),
            })),
        }
    }

    pub(crate) async fn published(&self, api: &str) -> Option<usize> {
        let inner = self.inner.as_ref()?;
        inner
            .state
            .lock()
            .await
            .apis
            .get(api)
            .map(|progress| progress.published)
    }

    pub(crate) async fn record_published(&self, api: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        let newly_complete = {
            let mut state = inner.state.lock().await;
            let Some(progress) = state.apis.get_mut(api) else {
                return false;
            };
            progress.published = progress.published.saturating_add(1);
            let complete = state
                .apis
                .values()
                .all(|progress| progress.stopped || progress.published >= progress.limit);
            let newly_complete = complete && !state.complete;
            state.complete = complete;
            newly_complete
        };
        if newly_complete {
            inner.completed.notify_waiters();
        }
        newly_complete
    }

    pub(crate) async fn record_stopped(&self, api: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        let newly_complete = {
            let mut state = inner.state.lock().await;
            let Some(progress) = state.apis.get_mut(api) else {
                return false;
            };
            progress.stopped = true;
            let complete = state
                .apis
                .values()
                .all(|progress| progress.stopped || progress.published >= progress.limit);
            let newly_complete = complete && !state.complete;
            state.complete = complete;
            newly_complete
        };
        if newly_complete {
            inner.completed.notify_waiters();
        }
        newly_complete
    }

    pub(crate) async fn wait_until_complete(&self) {
        let Some(inner) = &self.inner else {
            std::future::pending::<()>().await;
            return;
        };
        loop {
            let notified = inner.completed.notified();
            if inner.state.lock().await.complete {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn unscoped_recording_never_completes_from_case_limits() {
        let limits = ExplicitApiCaseLimits::default();

        assert!(
            tokio::time::timeout(Duration::from_millis(20), limits.wait_until_complete())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn every_explicit_api_must_reach_its_limit() {
        let limits = ExplicitApiCaseLimits::new([
            ("GET /api/fast".to_string(), 2),
            ("GET /api/slow".to_string(), 1),
        ]);

        assert!(!limits.record_published("GET /api/fast").await);
        assert!(!limits.record_published("GET /api/slow").await);
        assert!(limits.record_published("GET /api/fast").await);
        tokio::time::timeout(Duration::from_millis(20), limits.wait_until_complete())
            .await
            .unwrap();
        assert_eq!(limits.published("GET /api/fast").await, Some(2));
        assert_eq!(limits.published("GET /api/slow").await, Some(1));
    }

    #[tokio::test]
    async fn unknown_api_does_not_advance_completion() {
        let limits = ExplicitApiCaseLimits::new([("GET /api".to_string(), 1)]);

        assert!(!limits.record_published("GET /other").await);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), limits.wait_until_complete())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn zero_limits_are_complete_without_a_publication() {
        let limits = ExplicitApiCaseLimits::new([("GET /disabled".to_string(), 0)]);

        tokio::time::timeout(Duration::from_millis(20), limits.wait_until_complete())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stopped_api_satisfies_only_its_own_completion() {
        let limits = ExplicitApiCaseLimits::new([
            ("GET /api/failing".to_string(), 100),
            ("GET /api/passing".to_string(), 1),
        ]);

        assert!(!limits.record_stopped("GET /api/failing").await);
        assert!(limits.record_published("GET /api/passing").await);
        tokio::time::timeout(Duration::from_millis(20), limits.wait_until_complete())
            .await
            .unwrap();
    }
}
