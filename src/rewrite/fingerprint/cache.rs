use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::Fnv1a;

#[derive(Default)]
struct FingerprintCache {
    repository_files: HashMap<(PathBuf, bool), Fnv1a>,
    repositories: HashMap<PathBuf, String>,
    revision_matches: HashMap<(PathBuf, String), bool>,
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

pub(super) fn repository_files(root: &Path, review: bool) -> Option<Fnv1a> {
    CACHE.with(|slot| {
        slot.borrow()
            .as_ref()?
            .repository_files
            .get(&(root.to_path_buf(), review))
            .copied()
    })
}

pub(super) fn insert_repository_files(root: PathBuf, review: bool, hash: Fnv1a) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.repository_files.insert((root, review), hash);
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

pub(super) fn revision_matches(root: &Path, revision: &str) -> Option<bool> {
    CACHE.with(|slot| {
        slot.borrow()
            .as_ref()?
            .revision_matches
            .get(&(root.to_path_buf(), revision.to_owned()))
            .copied()
    })
}

pub(super) fn insert_revision_matches(root: PathBuf, revision: String, matches: bool) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.revision_matches.insert((root, revision), matches);
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
