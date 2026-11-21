use std::collections::HashMap;

use super::ReplaySource;

#[allow(dead_code)]
/// Stable positions of case-owned replay exchanges in one protocol inventory.
///
/// Replay inventories are immutable after startup; only exchange status changes.
/// Keeping their positions by case makes end-of-case verification proportional
/// to that case's dependencies instead of the complete recording inventory.
#[derive(Debug, Default)]
pub(crate) struct CaseExchangeIndex {
    by_case: HashMap<String, Vec<usize>>,
}

impl CaseExchangeIndex {
    #[allow(dead_code)]
    pub(crate) fn register(&mut self, source: ReplaySource, case_id: Option<&str>, index: usize) {
        if source != ReplaySource::Case {
            return;
        }
        if let Some(case_id) = case_id {
            self.by_case
                .entry(case_id.to_string())
                .or_default()
                .push(index);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn any(&self, case_id: &str, mut predicate: impl FnMut(usize) -> bool) -> bool {
        self.by_case
            .get(case_id)
            .is_some_and(|indices| indices.iter().copied().any(&mut predicate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visits_only_the_selected_case_positions() {
        let mut index = CaseExchangeIndex::default();
        for position in 0..10_000 {
            index.register(
                ReplaySource::Case,
                Some(&format!("case-{position}")),
                position,
            );
        }
        index.register(ReplaySource::Case, Some("selected"), 10_000);
        index.register(ReplaySource::Case, Some("selected"), 10_001);
        index.register(ReplaySource::Startup, Some("selected"), 10_002);

        let mut visited = Vec::new();
        assert!(!index.any("selected", |position| {
            visited.push(position);
            false
        }));
        assert_eq!(visited, [10_000, 10_001]);
    }
}
