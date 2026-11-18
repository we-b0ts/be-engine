//! Request-body I/O ownership before finite exchange matching can begin.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;

#[derive(Debug, Default, Clone)]
pub struct InputActivity {
    counts: Arc<Mutex<BTreeMap<Option<String>, usize>>>,
    pub changed: Arc<Notify>,
}

pub struct InputLease {
    activity: InputActivity,
    case: Option<String>,
}

impl traffic_protocol::connection::RequestInput for InputLease {}

impl InputActivity {
    pub fn begin(&self, case: Option<String>) -> InputLease {
        *self
            .counts
            .lock()
            .expect("input activity lock")
            .entry(case.clone())
            .or_default() += 1;
        self.changed.notify_waiters();
        InputLease {
            activity: self.clone(),
            case,
        }
    }
    pub fn has_in_flight(&self) -> bool {
        !self.counts.lock().expect("input activity lock").is_empty()
    }
    pub fn has_case_in_flight(&self) -> bool {
        self.counts
            .lock()
            .expect("input activity lock")
            .keys()
            .any(Option::is_some)
    }
}

impl Drop for InputLease {
    fn drop(&mut self) {
        let mut counts = self.activity.counts.lock().expect("input activity lock");
        let count = counts
            .get_mut(&self.case)
            .expect("live request input lease");
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.case);
        }
        drop(counts);
        self.activity.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_leases_keep_case_and_run_io_scopes_separate() {
        let activity = InputActivity::default();
        let case = activity.begin(Some("case-a".into()));
        let run = activity.begin(None);
        assert!(activity.has_in_flight() && activity.has_case_in_flight());
        drop(case);
        assert!(activity.has_in_flight());
        assert!(!activity.has_case_in_flight());
        drop(run);
        assert!(!activity.has_in_flight());
    }
}
