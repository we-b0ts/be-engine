//! Case-local admission order, independent of response delivery and report limits.
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub(super) struct RequestOrder {
    observed: BTreeMap<Option<String>, usize>,
}

impl RequestOrder {
    pub(super) fn reserve(&mut self, case: Option<&str>) -> usize {
        let next = self.observed.entry(case.map(str::to_owned)).or_default();
        let index = *next;
        *next += 1;
        index
    }

    // The caller must retain the replay mutex from selection until reporting.
    pub(super) fn latest(&self, case: Option<&str>) -> Option<usize> {
        self.observed.get(&case.map(str::to_owned))?.checked_sub(1)
    }
}

#[cfg(test)]
mod tests;
