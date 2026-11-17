use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

thread_local! {
    static GIT_ROOTS: RefCell<Option<HashMap<PathBuf, PathBuf>>> = const { RefCell::new(None) };
}

pub(super) fn scope<T>(operation: impl FnOnce() -> T) -> T {
    let owns_cache = GIT_ROOTS.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(HashMap::new());
            true
        }
    });
    let _guard = CacheGuard { owns_cache };
    operation()
}

pub(super) fn get(path: &Path) -> Option<PathBuf> {
    GIT_ROOTS.with(|slot| slot.borrow().as_ref()?.get(path).cloned())
}

pub(super) fn insert(path: PathBuf, root: PathBuf) {
    GIT_ROOTS.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache.insert(path, root);
        }
    });
}

struct CacheGuard {
    owns_cache: bool,
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        if self.owns_cache {
            GIT_ROOTS.with(|slot| *slot.borrow_mut() = None);
        }
    }
}
