//! Bounded physical-field analysis reuse, keyed by literal-free statement shape.
use super::{FieldAnalysis, analyze_shape};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, OnceLock},
};

const MAX_ENTRIES: usize = 256;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 1024 * 1024;
type Key = (Option<String>, String);

#[derive(Default)]
struct Cache {
    entries: HashMap<Key, (Option<Arc<FieldAnalysis>>, usize)>,
    order: VecDeque<Key>,
    bytes: usize,
}

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

#[cfg(test)]
thread_local! { pub(super) static PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

fn charge(key: &Key, analysis: Option<&FieldAnalysis>) -> usize {
    let identity = |field: &super::FieldIdentity| {
        64 + field.database.as_ref().map_or(0, String::len) + field.table.len() + field.column.len()
    };
    key.1.len().saturating_mul(2)
        + key.0.as_ref().map_or(0, String::len)
        + 128
        + analysis.map_or(0, |analysis| {
            analysis
                .bindings
                .iter()
                .map(|b| identity(&b.field) + b.field.column.len() + 48)
                .sum::<usize>()
                + analysis
                    .projections
                    .as_ref()
                    .map_or(0, |p| p.iter().flatten().map(identity).sum())
                + analysis.projection_labels.as_ref().map_or(0, |labels| {
                    labels.iter().map(|label| label.len() + 32).sum()
                })
        })
}

pub(super) fn get(shape: String, database: Option<&str>) -> Option<Arc<FieldAnalysis>> {
    let cache = CACHE.get_or_init(|| Mutex::new(Cache::default()));
    get_in(cache, shape, database)
}

fn get_in(
    cache: &Mutex<Cache>,
    shape: String,
    database: Option<&str>,
) -> Option<Arc<FieldAnalysis>> {
    let key = (database.map(str::to_owned), shape);
    if let Some((analysis, _)) = cache.lock().expect("SQL field cache").entries.get(&key) {
        return analysis.clone();
    }
    // AST work and potentially large deallocation stay outside the shared lock.
    #[cfg(test)]
    PARSES.with(|count| count.set(count.get() + 1));
    let analysis = analyze_shape(&key.1, database).map(Arc::new);
    let bytes = charge(&key, analysis.as_deref());
    if bytes > MAX_ENTRY_BYTES {
        return analysis;
    }
    let mut retired = Vec::new();
    let mut cache = cache.lock().expect("SQL field cache");
    if let Some((cached, _)) = cache.entries.get(&key) {
        return cached.clone();
    }
    while cache.entries.len() >= MAX_ENTRIES || cache.bytes + bytes > MAX_BYTES {
        let Some(oldest) = cache.order.pop_front() else {
            break;
        };
        if let Some(entry) = cache.entries.remove(&oldest) {
            cache.bytes -= entry.1;
            retired.push((oldest, entry));
        }
    }
    cache.bytes += bytes;
    cache.order.push_back(key.clone());
    cache.entries.insert(key, (analysis.clone(), bytes));
    drop(cache);
    drop(retired);
    analysis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_and_byte_bounds_hold_for_positive_and_negative_shapes() {
        let cache = Mutex::new(Cache::default());
        for index in 0..MAX_ENTRIES + 20 {
            get_in(
                &cache,
                format!("SELECT id FROM bounded_cache_{index} WHERE stamp > ?9"),
                Some("app"),
            );
            get_in(&cache, format!("unsupported_cache_{index}"), Some("app"));
        }
        let cache = cache.lock().unwrap();
        assert!(cache.entries.len() <= MAX_ENTRIES);
        assert!(cache.bytes <= MAX_BYTES);
    }

    #[test]
    fn changed_literal_values_and_binds_reuse_one_analysis_without_caching_values() {
        let cache = Mutex::new(Cache::default());
        let before = PARSES.with(|count| count.get());
        let shape = |sql| super::super::shape(&crate::sql::tokens(sql).unwrap()).unwrap();
        let source = get_in(
            &cache,
            shape("UPDATE cache_reuse SET stamp='source-secret' WHERE id=7"),
            Some("app"),
        )
        .unwrap();
        let target = get_in(
            &cache,
            shape("UPDATE cache_reuse SET stamp='target-secret' WHERE id=8"),
            Some("app"),
        )
        .unwrap();
        let bound = get_in(
            &cache,
            shape("UPDATE cache_reuse SET stamp=? WHERE id=?"),
            Some("app"),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&source, &target));
        assert!(Arc::ptr_eq(&source, &bound));
        assert_eq!(PARSES.with(|count| count.get()) - before, 1);
        assert!(!format!("{source:?}").contains("secret"));
        let before = PARSES.with(|count| count.get());
        assert!(get_in(&cache, "unsupported cached syntax".into(), None).is_none());
        assert!(get_in(&cache, "unsupported cached syntax".into(), None).is_none());
        assert_eq!(PARSES.with(|count| count.get()) - before, 1);
    }
}
