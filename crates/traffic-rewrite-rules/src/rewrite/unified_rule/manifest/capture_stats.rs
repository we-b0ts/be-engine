//! Test-only accounting of rule evidence payload reads.
use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path, PathBuf},
};

thread_local! {
    static CAPTURES: RefCell<BTreeMap<PathBuf, (usize, u64)>> = const {
        RefCell::new(BTreeMap::new())
    };
}

pub fn note_capture(path: &Path) {
    CAPTURES.with(|slot| slot.borrow_mut().entry(path.into()).or_default().0 += 1);
}

pub fn note_captured_bytes(path: &Path, bytes: u64) {
    CAPTURES.with(|slot| slot.borrow_mut().entry(path.into()).or_default().1 += bytes);
}

pub fn capture_stats() -> BTreeMap<PathBuf, (usize, u64)> {
    CAPTURES.with(|slot| slot.borrow().clone())
}

pub fn reset_capture_stats() {
    CAPTURES.with(|slot| slot.borrow_mut().clear());
}

#[cfg(test)]
mod tests;
