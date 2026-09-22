use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::Fnv1a;

#[derive(Default)]
struct FingerprintCache {
    repository_files: HashMap<PathBuf, Fnv1a>,
    repositories: HashMap<PathBuf, String>,
}

thread_local! {
    static CACHE: RefCell<Option<FingerprintCache>> = const { RefCell::new(None) };
}

pub(super) fn scope<T>(operation: impl FnOnce() -> T) -> T {
    let owns_cache = CACHE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(FingerprintCache::default());
            true
        }
    });
    let _guard = CacheGuard { owns_cache };
    operation()
}

pub(super) fn repository_files(root: &Path) -> Option<Fnv1a> {
    CACHE.with(|slot| slot.borrow().as_ref()?.repository_files.get(root).copied())
}

pub(super) fn insert_repository_files(root: PathBuf, hash: Fnv1a) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.repository_files.insert(root, hash);
        }
    });
}

pub(super) fn repository(root: &Path) -> Option<String> {
    CACHE.with(|slot| slot.borrow().as_ref()?.repositories.get(root).cloned())
}

pub(super) fn insert_repository(root: PathBuf, fingerprint: String) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.repositories.insert(root, fingerprint);
        }
    });
}

struct CacheGuard {
    owns_cache: bool,
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        if self.owns_cache {
            CACHE.with(|slot| *slot.borrow_mut() = None);
        }
    }
}
