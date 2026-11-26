//! Allocate stable implementer worktree slots under the round lock.

use std::{collections::BTreeSet, ffi::OsStr, os::unix::ffi::OsStrExt, process::Command};

use traffic_e2e::repository::implementer_worktree;

use super::*;

impl Repository {
    pub fn reserve_worktrees(&self, lock: &RoundLock, round: &mut Round) -> Result<()> {
        self.check_checkout(lock)?;
        let registered = self.registered_worktree_slots()?;
        let occupied: BTreeSet<_> = round.workflow.active_worktree_slots().collect();
        let mut options = 0..usize::MAX;
        round.workflow.reserve_worktrees(|| {
            for slot in &mut options {
                if occupied.contains(&slot) {
                    continue;
                }
                let path = implementer_worktree(&self.root, slot);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_dir() && registered.contains(&slot) => {
                        return Ok(slot);
                    }
                    Ok(_) => continue,
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        if !registered.contains(&slot) {
                            return Ok(slot);
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| format!("inspect {}", path.display()));
                    }
                }
            }
            anyhow::bail!("implementer worktree slots exhausted")
        })
    }

    fn registered_worktree_slots(&self) -> Result<BTreeSet<usize>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["worktree", "list", "--porcelain", "-z"])
            .output()
            .context("list Target worktrees")?;
        ensure!(output.status.success(), "unable to list Target worktrees");
        let sample = implementer_worktree(&self.root, 0);
        let parent = sample.parent().expect("implementer worktree parent");
        Ok(output
            .stdout
            .split(|byte| *byte == 0)
            .filter_map(|field| {
                let path = Path::new(OsStr::from_bytes(field.strip_prefix(b"worktree ")?));
                if path.parent() != Some(parent) {
                    return None;
                }
                let slot = path
                    .file_name()?
                    .to_str()?
                    .strip_prefix("api-implementer-")?
                    .parse()
                    .ok()?;
                (path == implementer_worktree(&self.root, slot)).then_some(slot)
            })
            .collect())
    }
}
