//! Immutable candidate postings and independent physical lane constraints.
use std::sync::Arc;
mod candidate;
mod lane;
pub use candidate::CandidateIndex;
mod postings;
pub use lane::{LaneIndex, LaneKey, LaneOwner};
pub use postings::Postings;

/// The two posting lists are merged by original inventory position. Exact and
/// rule-compatible candidates must never establish a different Source order.
#[derive(Debug, Clone)]
pub struct CandidateCursor {
    first: Arc<[usize]>,
    second: Option<Arc<[usize]>>,
    first_position: usize,
    second_position: usize,
    third: Option<Arc<[usize]>>,
    third_position: usize,
}

impl CandidateCursor {
    pub fn only(index: Option<usize>) -> Self {
        Self::new(index.into_iter().collect::<Vec<_>>().into())
    }
    pub fn new(indices: Arc<[usize]>) -> Self {
        Self {
            first: indices,
            second: None,
            first_position: 0,
            second_position: 0,
            third: None,
            third_position: 0,
        }
    }

    pub fn merge(self, other: Self) -> Self {
        assert!(self.second.is_none() && self.third.is_none() && other.third.is_none());
        assert_eq!(self.first_position, 0);
        assert_eq!(other.first_position, 0);
        Self {
            second: Some(other.first),
            third: other.second,
            ..self
        }
    }

    pub fn into_indices(self) -> Arc<[usize]> {
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
            (None, None) => usize::MAX,
        };
        let third = self
            .third
            .as_ref()
            .and_then(|indices| indices.get(self.third_position))
            .copied();
        let selected = third.map_or(selected, |third| selected.min(third));
        if selected == usize::MAX {
            return None;
        }
        self.first_position += usize::from(first == Some(selected));
        self.second_position += usize::from(second == Some(selected));
        self.third_position += usize::from(third == Some(selected));
        Some(selected)
    }
}

mod membership;
pub use membership::CaseMembership;
mod scope;
pub use scope::ScopePartition;
