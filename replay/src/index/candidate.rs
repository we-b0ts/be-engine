//! Typed lookup keys are supplied by adapters; postings retain Source order.
use super::{CandidateCursor, Postings};
use std::hash::Hash;

#[derive(Debug)]
pub struct CandidateIndex<K> {
    postings: Postings<K>,
}

impl<K> Default for CandidateIndex<K> {
    fn default() -> Self {
        Self {
            postings: Postings::default(),
        }
    }
}

impl<K: Clone + Eq + Hash> CandidateIndex<K> {
    pub fn register(&mut self, key: K, index: usize) {
        self.postings.register(key, index);
    }
    pub fn seal(&mut self) {
        self.postings.seal();
    }
    pub(crate) fn discard(&mut self, key: &K, index: usize) {
        self.postings.discard(key, index);
    }
    pub fn lookup(&self, key: &K) -> CandidateCursor {
        CandidateCursor::new(self.postings.lookup(key))
    }
}
