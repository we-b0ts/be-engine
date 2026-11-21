use std::{collections::HashMap, hash::Hash, sync::Arc};

#[derive(Debug, Default)]
struct Bucket {
    frozen: Arc<[usize]>,
    pending: Vec<usize>,
}

#[derive(Debug)]
pub struct Postings<K> {
    buckets: HashMap<K, Bucket>,
    changed: Vec<K>,
}

impl<K> Default for Postings<K> {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            changed: Vec::new(),
        }
    }
}

impl<K: Clone + Eq + Hash> Postings<K> {
    pub fn register(&mut self, key: K, index: usize) {
        let bucket = self.buckets.entry(key.clone()).or_default();
        let previous = bucket.pending.last().or_else(|| bucket.frozen.last());
        if previous == Some(&index) {
            return;
        }
        assert!(previous.is_none_or(|previous| *previous < index));
        if bucket.pending.is_empty() {
            self.changed.push(key);
        }
        bucket.pending.push(index);
    }

    pub fn seal(&mut self) {
        for key in self.changed.drain(..) {
            let bucket = self.buckets.get_mut(&key).expect("changed native bucket");
            let mut indices = Vec::with_capacity(bucket.frozen.len() + bucket.pending.len());
            indices.extend_from_slice(&bucket.frozen);
            indices.append(&mut bucket.pending);
            bucket.frozen = indices.into();
        }
    }

    pub fn lookup(&self, key: &K) -> Arc<[usize]> {
        self.buckets.get(key).map_or_else(
            || Arc::from([]),
            |bucket| {
                assert!(bucket.pending.is_empty(), "native index was not prepared");
                bucket.frozen.clone()
            },
        )
    }
}
