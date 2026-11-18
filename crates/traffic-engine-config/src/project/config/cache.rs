use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::super::model::{ProjectConfig, ResolvedProjectConfig};

#[derive(Default)]
struct ProjectCache {
    documents: HashMap<PathBuf, ProjectConfig>,
    resolutions: HashMap<PathBuf, ResolvedProjectConfig>,
}

thread_local! {
    static CACHE: RefCell<Option<ProjectCache>> = const { RefCell::new(None) };
}

pub fn scope<T>(operation: impl FnOnce() -> T) -> T {
    let owns_cache = CACHE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(ProjectCache::default());
            true
        }
    });
    let _guard = CacheGuard { owns_cache };
    operation()
}

pub fn get(root: &Path) -> Option<ResolvedProjectConfig> {
    CACHE.with(|slot| slot.borrow().as_ref()?.resolutions.get(root).cloned())
}

pub fn insert(root: PathBuf, project: ResolvedProjectConfig) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.resolutions.insert(root, project);
        }
    });
}

pub fn document(path: &Path) -> Option<ProjectConfig> {
    CACHE.with(|slot| slot.borrow().as_ref()?.documents.get(path).cloned())
}

pub fn insert_document(path: PathBuf, project: ProjectConfig) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.documents.insert(path, project);
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
