//! Freeze the managed Replay timer plan and isolate its Target-only socket.
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::replay::ReplayStreamTiming;

const PLAN_ENV: &str = "TRAFFIC_E2E_REPLAY_TIMER_PLAN";
const MAX_PLAN_BYTES: usize = 1_048_576;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
// A Unix socket needs write permission to connect. Only the owning host user
// can traverse the parent directory. Docker mounts the socket inode alone.
const MOUNTED_SOCKET_MODE: u32 = 0o622;

pub(crate) const TARGET_SOCKET: &str = "/traffic-e2e/replay/timer.sock";
pub(crate) const TARGET_SOCKET_ENV: &str = "BRZ_REPLAY_TIMER_SOCKET";

pub(crate) fn read_plan(
    root: &Path,
    timing: Option<ReplayStreamTiming>,
) -> Result<Option<Vec<u8>>> {
    if timing != Some(ReplayStreamTiming::Fast) {
        return Ok(None);
    }
    std::env::var_os(PLAN_ENV)
        .map(|path| {
            ensure!(!path.is_empty(), "{PLAN_ENV} is empty");
            let path = root.join(path);
            read_plan_file(&path)
                .with_context(|| format!("read Replay timer plan {}", path.display()))
        })
        .transpose()
}

fn read_plan_file(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        fs::metadata(path)?.is_file(),
        "Replay timer plan must be a file"
    );
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PLAN_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_PLAN_BYTES,
        "Replay timer plan is too large"
    );
    Ok(bytes)
}

pub(crate) struct ManagedTimer {
    directory: PathBuf,
    plan: PathBuf,
    socket: PathBuf,
}

impl ManagedTimer {
    pub(crate) fn stage(bytes: &[u8]) -> Result<Self> {
        let directory =
            Path::new("/tmp").join(format!("trp-timer-{}", uuid::Uuid::new_v4().simple()));
        DirBuilder::new()
            .mode(PRIVATE_DIR_MODE)
            .create(&directory)
            .context("create private Replay timer directory")?;
        let staged = Self {
            plan: directory.join("plan.json"),
            socket: directory.join("timer.sock"),
            directory,
        };
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(&staged.plan)
            .context("create frozen Replay timer plan")?
            .write_all(bytes)
            .context("write frozen Replay timer plan")?;
        Ok(staged)
    }

    pub(crate) fn replay_args(&self) -> [&std::ffi::OsStr; 4] {
        [
            std::ffi::OsStr::new("--timer-plan"),
            self.plan.as_os_str(),
            std::ffi::OsStr::new("--timer-socket"),
            self.socket.as_os_str(),
        ]
    }

    pub(crate) fn socket_for_target(&self) -> Result<&Path> {
        let directory = fs::symlink_metadata(&self.directory)
            .context("inspect private Replay timer directory before Target launch")?;
        let socket = fs::symlink_metadata(&self.socket)
            .context("inspect bound Replay timer socket before Target launch")?;
        ensure!(
            directory.is_dir()
                && directory.mode() & 0o777 == PRIVATE_DIR_MODE
                && socket.file_type().is_socket()
                && socket.uid() == directory.uid()
                && matches!(
                    socket.mode() & 0o777,
                    PRIVATE_FILE_MODE | MOUNTED_SOCKET_MODE
                ),
            "Replay timer socket is outside its private launch scope"
        );
        fs::set_permissions(&self.socket, Permissions::from_mode(MOUNTED_SOCKET_MODE))
            .context("allow the Target user to connect to its Replay timer mount")?;
        Ok(&self.socket)
    }
}

impl Drop for ManagedTimer {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.directory)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.directory.display(), %error, "remove Replay timer directory");
        }
    }
}

#[cfg(test)]
mod tests;
