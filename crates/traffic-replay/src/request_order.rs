//! Arrival order is reserved once, independent of completion order/report limits.
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct RequestOrder {
    observed: BTreeMap<Option<String>, usize>,
}
impl RequestOrder {
    pub fn reserve(&mut self, case: Option<&str>) -> usize {
        let next = self.observed.entry(case.map(str::to_owned)).or_default();
        let index = *next;
        *next += 1;
        index
    }
    /// Selection and reporting use the same observation owner.
    pub fn latest(&self, case: Option<&str>) -> Option<usize> {
        self.observed.get(&case.map(str::to_owned))?.checked_sub(1)
    }
}
