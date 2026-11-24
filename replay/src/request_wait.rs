//! Bounded pending requests wait on independently prepared Source scopes.
use crate::{EventKind, SequenceRuntime};
use anyhow::Result;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

pub struct RequestWait {
    scopes: Vec<ScopeWait>,
    pending: Option<crate::PendingRequest>,
    bytes: usize,
    request_grace: Duration,
}

struct ScopeWait {
    runtime: Arc<SequenceRuntime>,
    changed: tokio::sync::watch::Receiver<u64>,
    case: bool,
    missing: Option<(u64, Instant)>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MissingDependency {
    pub case_id: Option<String>,
    pub expected: crate::SourceEvent,
    pub ownership_revision: u64,
}

impl RequestWait {
    pub fn failed(&self) -> bool {
        self.scopes.iter().any(|scope| scope.runtime.failed())
    }
    pub fn new(
        scopes: impl IntoIterator<Item = (bool, Arc<SequenceRuntime>)>,
        bytes: usize,
    ) -> Option<Self> {
        Self::with_grace(scopes, bytes, Duration::from_millis(250))
    }

    pub fn with_grace(
        scopes: impl IntoIterator<Item = (bool, Arc<SequenceRuntime>)>,
        bytes: usize,
        request_grace: Duration,
    ) -> Option<Self> {
        let scopes: Vec<_> = scopes
            .into_iter()
            .map(|(case, runtime)| ScopeWait {
                changed: runtime.subscribe_requests(),
                runtime,
                case,
                missing: None,
            })
            .collect();
        (!scopes.is_empty()).then_some(Self {
            scopes,
            pending: None,
            bytes,
            request_grace,
        })
    }

    pub fn reserve(&mut self) -> Result<()> {
        if self.pending.is_none() {
            self.pending = Some(self.scopes[0].runtime.pending(self.bytes)?);
        }
        Ok(())
    }

    pub fn deadline(&mut self, overall: Instant) -> Option<Instant> {
        let mut deadline = None;
        for scope in &mut self.scopes {
            if scope.runtime.failed() {
                return None;
            }
            let Some(expected) = scope.runtime.expected() else {
                continue;
            };
            let until = if expected.kind == EventKind::Request
                && !scope.runtime.event_is_gated(expected.sequence)
            {
                if scope
                    .missing
                    .as_ref()
                    .is_none_or(|(sequence, _)| *sequence != expected.sequence)
                {
                    scope.missing = Some((expected.sequence, Instant::now() + self.request_grace));
                }
                scope
                    .missing
                    .expect("missing request deadline")
                    .1
                    .min(overall)
            } else {
                overall
            };
            deadline = Some(deadline.map_or(until, |before: Instant| before.min(until)));
        }
        deadline
    }

    pub async fn wait(&mut self, deadline: Instant) -> bool {
        use futures_util::{StreamExt, stream::FuturesUnordered};
        let mut changed: FuturesUnordered<_> = self
            .scopes
            .iter_mut()
            .map(|scope| scope.changed.changed())
            .collect();
        matches!(
            tokio::time::timeout_at(deadline, changed.next()).await,
            Ok(Some(Ok(())))
        )
    }

    pub fn diagnose(&self, revision: u64, case: Option<&str>) -> Vec<MissingDependency> {
        self.scopes
            .iter()
            .filter_map(|scope| {
                Some(MissingDependency {
                    case_id: scope.case.then_some(case).flatten().map(str::to_owned),
                    expected: scope.runtime.missing_request(revision)?,
                    ownership_revision: revision,
                })
            })
            .collect()
    }
}
