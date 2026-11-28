use std::collections::{BTreeMap, BTreeSet};

use super::model::CaseStatus;

pub(super) struct ApiFailureLimit {
    limit: usize,
    failures: BTreeMap<String, usize>,
    stopped: BTreeSet<String>,
}

impl ApiFailureLimit {
    pub(super) fn new(limit: usize) -> Self {
        debug_assert!(limit > 0);
        Self {
            limit,
            failures: BTreeMap::new(),
            stopped: BTreeSet::new(),
        }
    }

    pub(super) fn should_execute(&self, group_id: &str) -> bool {
        !self.stopped.contains(group_id)
    }

    pub(super) fn observe(&mut self, group_id: &str, status: CaseStatus) -> bool {
        if !matches!(status, CaseStatus::Failed | CaseStatus::Incomplete) {
            return false;
        }
        let failures = self.failures.entry(group_id.to_string()).or_default();
        *failures = failures.saturating_add(1);
        if *failures < self.limit {
            return false;
        }
        self.stopped.insert(group_id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_only_the_api_that_reaches_the_limit() {
        let mut limit = ApiFailureLimit::new(2);

        assert!(!limit.observe("GET /a", CaseStatus::Failed));
        assert!(!limit.observe("GET /b", CaseStatus::Passed));
        assert!(limit.observe("GET /a", CaseStatus::Incomplete));
        assert!(!limit.should_execute("GET /a"));
        assert!(limit.should_execute("GET /b"));
    }
}
