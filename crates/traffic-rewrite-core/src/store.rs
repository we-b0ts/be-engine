//! Durable workflow snapshots and process ownership independent of host services.
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, ensure};

const INCOMPLETE_LOCK_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowLockState {
    Absent,
    Live,
    Stale,
}

pub struct SnapshotStore {
    root: PathBuf,
    state_path: PathBuf,
}

impl SnapshotStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            state_path: root.join("state.json"),
            root,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }
    pub fn exists(&self) -> bool {
        self.state_path.is_file()
    }

    pub fn snapshot_bytes(&self) -> Result<Option<Vec<u8>>> {
        match fs::read(&self.state_path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!("failed to read rewrite state {}", self.state_path.display())
            }),
        }
    }

    pub fn write_snapshot(&self, payload: &[u8], revision: u64) -> Result<()> {
        fs::create_dir_all(&self.root).with_context(|| {
            format!(
                "failed to create rewrite state root {}",
                self.root.display()
            )
        })?;
        let temporary = self.root.join(format!(
            ".state.json.tmp.{}.{}",
            std::process::id(),
            revision
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("failed to reserve {}", temporary.display()))?;
        let result = (|| -> Result<()> {
            file.write_all(payload)?;
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

    pub fn try_lock(&self) -> Result<Option<WorkflowLock>> {
        fs::create_dir_all(&self.root).with_context(|| {
            format!(
                "failed to create rewrite state root {}",
                self.root.display()
            )
        })?;
        let path = self.root.join("lock");
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let lock = WorkflowLock { path };
                writeln!(file, "{}", std::process::id())?;
                file.sync_all()?;
                Ok(Some(lock))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(error).context("failed to acquire rewrite workflow lock"),
        }
    }

    pub fn lock(&self) -> Result<WorkflowLock> {
        self.try_lock()?.context(
            "rewrite workflow is already being advanced; inspect `backend-rewrite status` and wait when it returns `wait_required`",
        )
    }

    pub fn lock_state(&self) -> Result<WorkflowLockState> {
        let path = self.root.join("lock");
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WorkflowLockState::Absent);
            }
            Err(error) => return Err(error).context("failed to read rewrite lock"),
        };
        if let Ok(pid) = raw.trim().parse::<u32>() {
            return Ok(if process_exists(pid) {
                WorkflowLockState::Live
            } else {
                WorkflowLockState::Stale
            });
        }
        let modified = fs::metadata(&path)?
            .modified()
            .context("rewrite lock has no modification time")?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        Ok(if age < INCOMPLETE_LOCK_GRACE {
            WorkflowLockState::Live
        } else {
            WorkflowLockState::Stale
        })
    }

    pub fn owns_lock(&self) -> Result<bool> {
        match fs::read_to_string(self.root.join("lock")) {
            Ok(raw) => Ok(raw.trim().parse::<u32>().ok() == Some(std::process::id())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).context("failed to read rewrite lock owner"),
        }
    }

    pub fn recover_lock(&self) -> Result<bool> {
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

pub struct WorkflowLock {
    path: PathBuf,
}

impl Drop for WorkflowLock {
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
