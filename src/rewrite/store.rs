use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, ensure};

use super::model::{RewriteState, STATE_VERSION};

const INCOMPLETE_LOCK_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RewriteLockState {
    Absent,
    Live,
    Stale,
}

pub(super) struct RewriteStore {
    root: PathBuf,
    target_root: PathBuf,
    state_path: PathBuf,
}

impl RewriteStore {
    pub(super) fn new(target_root: &Path) -> Result<Self> {
        let target_root = fs::canonicalize(target_root)
            .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
        let root = crate::internal_runtime::root(&target_root).join("rewrite");
        Ok(Self {
            state_path: root.join("state.json"),
            target_root,
            root,
        })
    }

    pub(super) fn load(&self) -> Result<Option<RewriteState>> {
        let bytes = match fs::read(&self.state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read rewrite state {}", self.state_path.display())
                });
            }
        };
        let mut state: RewriteState = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid rewrite state {}", self.state_path.display()))?;
        ensure!(
            state.version == STATE_VERSION,
            "unsupported rewrite state version {}",
            state.version
        );
        super::worker::events::overlay(&self.target_root, &mut state)?;
        if state.api_inventory.is_empty()
            && state.phase != super::model::RewritePhase::RecordingRequired
        {
            super::inventory::initialize_legacy(&mut state);
        }
        super::regression_scope::apply(&self.target_root, &mut state)?;
        Ok(Some(state))
    }

    pub(super) fn save(&self, state: &RewriteState) -> Result<()> {
        let _feedback = super::worker::events::lock(&self.target_root)?;
        let mut state = state.clone();
        super::worker::events::overlay(&self.target_root, &mut state)?;
        fs::create_dir_all(&self.root).with_context(|| {
            format!(
                "failed to create rewrite state root {}",
                self.root.display()
            )
        })?;
        let mut payload = serde_json::to_vec_pretty(&state)?;
        payload.push(b'\n');
        let temporary = self.root.join(format!(
            ".state.json.tmp.{}.{}",
            std::process::id(),
            state.revision
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("failed to reserve {}", temporary.display()))?;
        let result = (|| -> Result<()> {
            file.write_all(&payload)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.state_path).with_context(|| {
                format!(
                    "failed to publish rewrite state {}",
                    self.state_path.display()
                )
            })?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    pub(super) fn try_lock(&self) -> Result<Option<RewriteLock>> {
        if super::execution::owned_by_other_process(&self.target_root)? {
            return Ok(None);
        }
        fs::create_dir_all(&self.root).with_context(|| {
            format!(
                "failed to create rewrite state root {}",
                self.root.display()
            )
        })?;
        let path = self.root.join("lock");
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let lock = RewriteLock { path };
                writeln!(file, "{}", std::process::id())?;
                file.sync_all()?;
                Ok(Some(lock))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(error).context("failed to acquire rewrite workflow lock"),
        }
    }

    pub(super) fn lock(&self) -> Result<RewriteLock> {
        self.try_lock()?.context(
            "rewrite workflow is already being advanced; inspect `backend-rewrite status` and wait when it returns `wait_required`",
        )
    }

    pub(super) fn lock_state(&self) -> Result<RewriteLockState> {
        let path = self.root.join("lock");
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RewriteLockState::Absent);
            }
            Err(error) => return Err(error).context("failed to read rewrite lock"),
        };
        if let Ok(pid) = raw.trim().parse::<u32>() {
            return Ok(if process_exists(pid) {
                RewriteLockState::Live
            } else {
                RewriteLockState::Stale
            });
        }
        let modified = fs::metadata(&path)?
            .modified()
            .context("rewrite lock has no modification time")?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        Ok(if age < INCOMPLETE_LOCK_GRACE {
            RewriteLockState::Live
        } else {
            RewriteLockState::Stale
        })
    }

    pub(super) fn recover_lock(&self) -> Result<bool> {
        let path = self.root.join("lock");
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("failed to read rewrite lock"),
        };
        match raw.trim().parse::<u32>() {
            Ok(pid) => ensure!(
                !process_exists(pid),
                "rewrite coordinator process {pid} is still active"
            ),
            Err(_) => {
                let modified = fs::metadata(&path)?
                    .modified()
                    .context("rewrite lock has no modification time")?;
                let age = SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                ensure!(
                    age >= INCOMPLETE_LOCK_GRACE,
                    "rewrite lock is still being initialized; execute `backend-rewrite recover` again"
                );
            }
        }
        fs::remove_file(&path).context("failed to remove stale rewrite lock")?;
        Ok(true)
    }
}

pub(super) struct RewriteLock {
    path: PathBuf,
}

impl Drop for RewriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        let result = unsafe { libc::kill(pid, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::test_state;

    #[test]
    fn state_is_atomically_replaced_and_lock_is_exclusive() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::internal_runtime::root(target.path())).unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        let mut state = test_state();
        store.save(&state).unwrap();
        state.bump();
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().unwrap().revision, 2);

        let lock = store.lock().unwrap();
        assert_eq!(store.lock_state().unwrap(), RewriteLockState::Live);
        assert!(store.try_lock().unwrap().is_none());
        assert!(store.lock().is_err());
        drop(lock);
        assert_eq!(store.lock_state().unwrap(), RewriteLockState::Absent);
        assert!(store.try_lock().unwrap().is_some());
    }

    #[test]
    fn recover_removes_an_incomplete_lock_without_exposing_it_to_callers() {
        let target = tempfile::tempdir().unwrap();
        let store = RewriteStore::new(target.path()).unwrap();
        fs::create_dir_all(&store.root).unwrap();
        fs::write(store.root.join("lock"), []).unwrap();

        assert!(store.recover_lock().is_err());
        let lock_file = File::options()
            .write(true)
            .open(store.root.join("lock"))
            .unwrap();
        lock_file
            .set_times(
                std::fs::FileTimes::new().set_modified(
                    SystemTime::now() - INCOMPLETE_LOCK_GRACE - Duration::from_secs(1),
                ),
            )
            .unwrap();

        assert_eq!(store.lock_state().unwrap(), RewriteLockState::Stale);
        assert!(store.recover_lock().unwrap());
        assert!(store.try_lock().unwrap().is_some());
    }
}
