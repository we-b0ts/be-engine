//! Immutable native candidate postings; admission and consumption stay protocol owned.
use std::sync::Arc;

use super::ReplaySource;

mod keys;
mod lane;
mod postings;
pub(in crate::replay) use keys::{HttpKey, MysqlCommand, MysqlKey, RedisKey, ScopePartition};
pub(in crate::replay) use lane::{LaneIndex, LaneKey, LaneOwner};
pub(in crate::replay) use postings::Postings;

#[cfg(test)]
mod tests;

/// The two posting lists are merged by original inventory position. Exact and
/// rule-compatible candidates must never establish a different Source order.
#[derive(Debug, Clone)]
pub(in crate::replay) struct CandidateCursor {
    first: Arc<[usize]>,
    second: Option<Arc<[usize]>>,
    first_position: usize,
    second_position: usize,
}

impl CandidateCursor {
    fn new(indices: Arc<[usize]>) -> Self {
        Self {
            first: indices,
            second: None,
            first_position: 0,
            second_position: 0,
        }
    }

    pub(in crate::replay) fn merge(self, other: Self) -> Self {
        assert!(self.second.is_none() && other.second.is_none());
        assert_eq!(self.first_position, 0);
        assert_eq!(other.first_position, 0);
        Self {
            second: Some(other.first),
            ..self
        }
    }

    pub(in crate::replay) fn into_indices(self) -> Arc<[usize]> {
        assert!(self.second.is_none());
        self.first
    }
}

impl Iterator for CandidateCursor {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.first.get(self.first_position).copied();
        let second = self
            .second
            .as_ref()
            .and_then(|indices| indices.get(self.second_position))
            .copied();
        let selected = match (first, second) {
            (Some(first), Some(second)) => first.min(second),
            (Some(index), None) | (None, Some(index)) => index,
            (None, None) => return None,
        };
        self.first_position += usize::from(first == Some(selected));
        self.second_position += usize::from(second == Some(selected));
        Some(selected)
    }
}

pub(in crate::replay) enum NativeQuery<'a> {
    Http(&'a HttpKey),
    Redis(&'a RedisKey),
    Mysql(&'a MysqlKey),
}

pub(in crate::replay) enum NativeKey {
    Http(HttpKey),
    Redis(RedisKey),
    Mysql(MysqlKey),
}

pub(in crate::replay) trait CandidateLookup {
    fn lookup(&self, query: NativeQuery<'_>) -> CandidateCursor;
}

#[derive(Debug)]
pub(in crate::replay) enum ProtocolIndex {
    Http(Postings<HttpKey>),
    Redis(Postings<RedisKey>),
    Mysql(Postings<MysqlKey>),
}

impl ProtocolIndex {
    pub(in crate::replay) fn http() -> Self {
        Self::Http(Postings::default())
    }

    pub(in crate::replay) fn redis() -> Self {
        Self::Redis(Postings::default())
    }

    pub(in crate::replay) fn mysql() -> Self {
        Self::Mysql(Postings::default())
    }

    pub(in crate::replay) fn register(&mut self, key: NativeKey, index: usize) {
        match (self, key) {
            (Self::Http(postings), NativeKey::Http(key)) => postings.register(key, index),
            (Self::Redis(postings), NativeKey::Redis(key)) => postings.register(key, index),
            (Self::Mysql(postings), NativeKey::Mysql(key)) => postings.register(key, index),
            _ => panic!("native candidate registration crossed protocol indexes"),
        }
    }

    /// Freeze only changed buckets during preparation, not the complete inventory.
    pub(in crate::replay) fn seal(&mut self) {
        match self {
            Self::Http(postings) => postings.seal(),
            Self::Redis(postings) => postings.seal(),
            Self::Mysql(postings) => postings.seal(),
        }
    }
}

impl CandidateLookup for ProtocolIndex {
    fn lookup(&self, query: NativeQuery<'_>) -> CandidateCursor {
        let indices = match (self, query) {
            (Self::Http(postings), NativeQuery::Http(key)) => postings.lookup(key),
            (Self::Redis(postings), NativeQuery::Redis(key)) => postings.lookup(key),
            (Self::Mysql(postings), NativeQuery::Mysql(key)) => postings.lookup(key),
            _ => panic!("native candidate query crossed protocol indexes"),
        };
        CandidateCursor::new(indices)
    }
}
