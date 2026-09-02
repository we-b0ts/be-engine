use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UpstreamDispatchOrder {
    BaselineThenCandidate,
    CandidateThenBaseline,
}

/// Assigns one fixed, balanced source/target dispatch order to each admitted
/// comparison case in this recorder process.
pub(super) struct ComparisonDispatchSchedule {
    seed: u64,
    next_case: AtomicU64,
}

impl ComparisonDispatchSchedule {
    pub(super) fn randomized() -> Result<Self> {
        let mut seed = [0_u8; 8];
        getrandom::fill(&mut seed).map_err(|error| {
            anyhow::anyhow!("failed to seed comparison dispatch order: {error}")
        })?;
        Ok(Self::from_seed(u64::from_le_bytes(seed)))
    }

    fn from_seed(seed: u64) -> Self {
        Self {
            seed,
            next_case: AtomicU64::new(0),
        }
    }

    pub(super) fn next(&self) -> UpstreamDispatchOrder {
        let case_index = self.next_case.fetch_add(1, Ordering::Relaxed);
        let candidate_first = candidate_first(self.seed, case_index / 2);
        let candidate_first = if case_index.is_multiple_of(2) {
            candidate_first
        } else {
            !candidate_first
        };
        if candidate_first {
            UpstreamDispatchOrder::CandidateThenBaseline
        } else {
            UpstreamDispatchOrder::BaselineThenCandidate
        }
    }
}

fn candidate_first(seed: u64, pair_index: u64) -> bool {
    splitmix64(seed.wrapping_add(pair_index)) & 1 == 1
}

fn splitmix64(value: u64) -> u64 {
    let value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_same_order_for_the_same_seed() {
        let first = ComparisonDispatchSchedule::from_seed(42);
        let second = ComparisonDispatchSchedule::from_seed(42);

        let first_orders = (0..12).map(|_| first.next()).collect::<Vec<_>>();
        let second_orders = (0..12).map(|_| second.next()).collect::<Vec<_>>();

        assert_eq!(first_orders, second_orders);
    }

    #[test]
    fn balances_each_adjacent_pair() {
        let schedule = ComparisonDispatchSchedule::from_seed(7);
        let orders = (0..20).map(|_| schedule.next()).collect::<Vec<_>>();

        for pair in orders.chunks_exact(2) {
            assert_ne!(pair[0], pair[1]);
        }
    }
}
