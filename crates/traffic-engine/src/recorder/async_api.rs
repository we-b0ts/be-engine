//! Protocol-independent asynchronous completion and ordered scenario selection.
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::{
    any::Any,
    sync::atomic::{AtomicU32, Ordering},
};
use uuid::Uuid;

mod selection;
#[cfg(test)]
mod tests;
pub use selection::AsyncScope;

pub(crate) const MAX_OCCURRENCE_OBSERVATIONS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncEndReason {
    Resource,
    DependencyFailure,
    Timeout,
    Stopped,
    Idle,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsyncSignal {
    pub end_reason: AsyncEndReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resource_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) event_type: Option<&'static str>,
}

pub(crate) trait CompletionRule: std::fmt::Debug + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn requires_response_selection(&self) -> bool;
    fn response_matches(&self, body: Option<&Value>) -> bool;
    fn all_ends_matched(&self) -> bool;
    fn observe_recorded(&self, event: &Value) -> Result<Option<AsyncSignal>>;
}

pub(crate) trait CompletionEvent {
    fn identity(&self) -> Option<Uuid>;
    fn evaluate(&self, rule: &dyn CompletionRule) -> Option<AsyncSignal>;
}

pub(crate) struct CapturedCompletion<'a> {
    pub(crate) event: &'a traffic_protocol::capture::CaptureSnapshot,
    pub(crate) identity: Option<Uuid>,
}

impl CompletionEvent for CapturedCompletion<'_> {
    fn identity(&self) -> Option<Uuid> {
        self.identity
    }
    fn evaluate(&self, rule: &dyn CompletionRule) -> Option<AsyncSignal> {
        rule.observe_recorded(self.event.payload())
            .unwrap_or_else(|_| {
                Some(AsyncSignal {
                    end_reason: AsyncEndReason::DependencyFailure,
                    resource_index: None,
                    event_type: Some(self.event.kind()),
                })
            })
    }
}

pub(crate) trait CompletionSource: std::fmt::Debug + Send + Sync {
    fn is_empty(&self) -> bool;
    fn select(&self, request: &Value, response: &Value) -> Result<Option<AsyncScope>>;
    fn requirements(&self, captured: Option<&Value>) -> Arc<dyn Any + Send + Sync>;
}

use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct CompletionPolicy(Option<Arc<dyn CompletionSource>>);

#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct CompletionRequirements(Option<Arc<dyn Any + Send + Sync>>);

impl CompletionRequirements {
    #[allow(dead_code)]
    pub(crate) fn get<T: 'static>(&self) -> Option<&T> {
        self.0.as_ref()?.downcast_ref()
    }
}

impl CompletionPolicy {
    pub(crate) fn new(source: impl CompletionSource + 'static) -> Self {
        Self(Some(Arc::new(source)))
    }
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_none_or(|source| source.is_empty())
    }
    pub fn select(&self, request: &Value, response: &Value) -> Result<Option<AsyncScope>> {
        self.0
            .as_ref()
            .map_or(Ok(None), |source| source.select(request, response))
    }
    pub fn requirements(&self, captured: Option<&Value>) -> CompletionRequirements {
        CompletionRequirements(self.0.as_ref().map(|source| source.requirements(captured)))
    }
}

#[derive(Debug)]
pub(crate) struct ResourceCompletion {
    expected: usize,
    matched: AtomicU32,
}

impl ResourceCompletion {
    pub(crate) fn new(expected: usize) -> Self {
        Self {
            expected,
            matched: AtomicU32::new(0),
        }
    }
    pub(crate) fn observe(&self, indexes: u32, event_type: &'static str) -> Option<AsyncSignal> {
        let valid = 1_u32
            .checked_shl(self.expected as u32)
            .map_or(u32::MAX, |end| end - 1);
        if indexes == 0 || indexes & !valid != 0 {
            return None;
        }
        self.matched.fetch_or(indexes, Ordering::AcqRel);
        Some(AsyncSignal {
            end_reason: AsyncEndReason::Resource,
            resource_index: Some(indexes.trailing_zeros() as usize),
            event_type: Some(event_type),
        })
    }
    pub(crate) fn is_complete(&self) -> bool {
        self.expected != 0
            && self.matched.load(Ordering::Acquire).count_ones() as usize == self.expected
    }
    #[cfg(test)]
    pub(crate) fn matched_mask(&self) -> u32 {
        self.matched.load(Ordering::Acquire)
    }
}
