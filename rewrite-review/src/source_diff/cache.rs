use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct GitReadCache {
    outputs: HashMap<(PathBuf, Vec<String>), Vec<u8>>,
    pr_bases: HashMap<(PathBuf, String), String>,
}

thread_local! {
    static CACHE: RefCell<Option<GitReadCache>> = const { RefCell::new(None) };
}

pub fn scope<T>(operation: impl FnOnce() -> T) -> T {
    let owns_cache = CACHE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(GitReadCache::default());
            true
        }
    });
    let _guard = CacheGuard { owns_cache };
    operation()
}

pub fn output(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    CACHE.with(|slot| {
        slot.borrow()
            .as_ref()?
            .outputs
            .get(&output_key(root, args))
            .cloned()
    })
}

pub fn insert_output(root: &Path, args: &[&str], output: &[u8]) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache
                .outputs
                .insert(output_key(root, args), output.to_vec());
        }
    });
}

fn output_key(root: &Path, args: &[&str]) -> (PathBuf, Vec<String>) {
    (
        root.to_path_buf(),
        args.iter().map(|arg| (*arg).to_owned()).collect(),
    )
}

pub fn pr_base(root: &Path, branch: &str) -> Option<String> {
    CACHE.with(|slot| {
        slot.borrow()
            .as_ref()?
            .pr_bases
            .get(&(root.to_path_buf(), branch.to_owned()))
            .cloned()
    })
}

pub fn insert_pr_base(root: &Path, branch: &str, resolved: &str) {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            cache
                .pr_bases
                .insert((root.to_path_buf(), branch.to_owned()), resolved.to_owned());
        }
    });
}

pub fn clear() {
    CACHE.with(|slot| {
        if let Some(cache) = slot.borrow_mut().as_mut() {
            *cache = GitReadCache::default();
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

#[cfg(test)]
mod tests;
