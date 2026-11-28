//! Branch-local implementation obligations for the committed route catalog.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use traffic_e2e::{
    event_work::{ApiConfirmation, ApiGrouping},
    session::RecordedApi,
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ApiBacklog {
    methods: BTreeMap<String, BTreeSet<String>>,
    pending: BTreeSet<String>,
}

impl ApiBacklog {
    pub fn observe(&mut self, inventory: &[RecordedApi]) {
        let mut methods_by_pattern = BTreeMap::<&str, Vec<&RecordedApi>>::new();
        for api in inventory {
            if let Some(pattern) = &api.case_pattern {
                methods_by_pattern.entry(pattern).or_default().push(api);
            }
        }
        for (pattern, apis) in methods_by_pattern {
            let already_seen = self.methods.contains_key(pattern);
            let methods = self.methods.entry(pattern.to_owned()).or_default();
            for api in apis {
                if methods.insert(api.method.clone()) && already_seen {
                    self.pending.insert(api.api.clone());
                }
            }
        }
    }

    pub fn register_groupings(&mut self, rows: &[ApiGrouping]) {
        for row in rows {
            let (method, _) = row.api.split_once(' ').expect("validated API label");
            self.register(method, &row.case_pattern);
        }
    }

    pub fn restore_pending(&mut self, api: &ApiConfirmation) {
        if let Some((method, pattern)) = identity(api) {
            self.register(method, pattern);
        }
    }

    fn register(&mut self, method: &str, pattern: &str) {
        self.methods
            .entry(pattern.to_owned())
            .or_default()
            .insert(method.to_owned());
        self.pending.insert(format!("{method} {pattern}"));
    }

    pub fn pending(&self, label: &str) -> bool {
        self.pending.contains(label)
    }

    pub fn pending_api(&self, api: &ApiConfirmation) -> bool {
        identity(api).is_some_and(|(method, pattern)| self.pending(&format!("{method} {pattern}")))
    }

    pub fn complete(&mut self, apis: Vec<ApiConfirmation>) {
        for api in &apis {
            if let Some((method, pattern)) = identity(api) {
                self.pending.remove(&format!("{method} {pattern}"));
            }
        }
    }
}

pub(super) fn identity(api: &ApiConfirmation) -> Option<(&str, &str)> {
    let (method, _) = api.api.split_once(' ')?;
    Some((method, api.case_pattern.as_deref()?))
}
