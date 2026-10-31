//! Shared bounded uniqueness proof for diagnostic native candidates.
//! Native adapters retain eligibility, ordering and actual delivery ownership.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SearchFailure {
    BudgetExhausted,
    Ambiguous,
}

#[derive(Debug)]
pub(super) struct UniqueCandidate<T> {
    budget: usize,
    visited: usize,
    selected: Option<(usize, T)>,
    failed: Option<SearchFailure>,
}

impl<T> UniqueCandidate<T> {
    pub(super) fn new(budget: usize) -> Self {
        Self {
            budget,
            visited: 0,
            selected: None,
            failed: None,
        }
    }

    /// Count every eligible preview, including failed and lane-blocked ones.
    pub(super) fn inspect(&mut self) -> Result<(), SearchFailure> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        self.visited += 1;
        if self.visited > self.budget {
            // A partial search cannot establish unique eligibility.
            self.selected = None;
            self.failed = Some(SearchFailure::BudgetExhausted);
            Err(SearchFailure::BudgetExhausted)
        } else {
            Ok(())
        }
    }

    pub(super) fn accept(&mut self, index: usize, value: T) -> Result<(), SearchFailure> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.selected.is_some() {
            self.selected = None;
            self.failed = Some(SearchFailure::Ambiguous);
            Err(SearchFailure::Ambiguous)
        } else {
            self.selected = Some((index, value));
            Ok(())
        }
    }

    pub(super) fn finish(self) -> Option<(usize, T)> {
        self.selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_or_ambiguous_search_cannot_publish_a_unique_candidate() {
        let mut budget = UniqueCandidate::new(1);
        budget.inspect().unwrap();
        budget.accept(7, "pending").unwrap();
        assert_eq!(budget.inspect(), Err(SearchFailure::BudgetExhausted));
        assert!(budget.finish().is_none());

        let mut ambiguous = UniqueCandidate::new(3);
        ambiguous.inspect().unwrap();
        ambiguous.accept(7, "first").unwrap();
        ambiguous.inspect().unwrap();
        assert_eq!(ambiguous.accept(9, "second"), Err(SearchFailure::Ambiguous));
        assert_eq!(ambiguous.accept(12, "late"), Err(SearchFailure::Ambiguous));
        assert!(ambiguous.finish().is_none());
    }

    #[test]
    fn failed_previews_count_but_do_not_erase_the_single_eligible_candidate() {
        let mut search = UniqueCandidate::new(3);
        search.inspect().unwrap();
        search.inspect().unwrap();
        search.accept(11, "native proposal").unwrap();
        search.inspect().unwrap();
        assert_eq!(search.finish(), Some((11, "native proposal")));
    }
}
