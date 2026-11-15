//! Cache whether an immutable Source SQL occurrence selects any field formats.
use super::*;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

const MAX_OCCURRENCES: usize = 65_536;

#[derive(Debug, Default)]
pub(super) struct Entry {
    pub(super) authored: Option<bool>,
    pub(super) any: Option<bool>,
}

#[derive(Debug, Default)]
pub(super) struct Cache {
    epoch: u64,
    inventory_len: usize,
    identity: Option<ReplaySessionIdentity>,
    policy: Weak<crate::policy::CompiledPolicy>,
    entries: HashMap<usize, Entry>,
}

impl Cache {
    pub(super) fn prepare(
        &mut self,
        epoch: u64,
        inventory_len: usize,
        identity: &ReplaySessionIdentity,
        policy: &Arc<crate::policy::CompiledPolicy>,
    ) {
        let policy = Arc::downgrade(policy);
        if self.epoch == epoch
            && self.inventory_len == inventory_len
            && self.identity.as_ref() == Some(identity)
            && self.policy.ptr_eq(&policy)
        {
            return;
        }
        self.epoch = epoch;
        self.inventory_len = inventory_len;
        self.identity = Some(identity.clone());
        self.policy = policy;
        self.entries.clear();
    }

    pub(super) fn entry(&mut self, index: usize) -> Option<&mut Entry> {
        (self.entries.len() < MAX_OCCURRENCES || self.entries.contains_key(&index))
            .then(|| self.entries.entry(index).or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cache_reuses_only_the_same_replay_scope_and_resource() {
        let document =
            serde_json::from_value(serde_json::json!({"format":"traffic-policy/v3"})).unwrap();
        let policy = Arc::new(crate::policy::compile_policy(&document).unwrap());
        let identity = ReplaySessionIdentity {
            target: None,
            database: Some("one".into()),
            username: None,
        };
        let mut cache = Cache::default();
        cache.prepare(1, 10, &identity, &policy);
        cache.entry(3).unwrap().any = Some(false);
        cache.prepare(1, 10, &identity, &policy);
        assert_eq!(cache.entry(3).unwrap().any, Some(false));

        cache.prepare(1, 11, &identity, &policy);
        assert_eq!(cache.entry(3).unwrap().any, None);
        cache.entry(3).unwrap().authored = Some(true);
        cache.prepare(2, 11, &identity, &policy);
        assert_eq!(cache.entry(3).unwrap().authored, None);

        cache.entry(3).unwrap().any = Some(false);
        let mut changed = identity;
        changed.database = Some("two".into());
        cache.prepare(2, 11, &changed, &policy);
        assert_eq!(cache.entry(3).unwrap().any, None);
    }
}
