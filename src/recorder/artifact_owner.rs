use std::ffi::CString;
use std::fmt;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactOwner {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl ArtifactOwner {
    pub fn new(uid: libc::uid_t, gid: libc::gid_t) -> Self {
        Self { uid, gid }
    }

    pub fn uid(self) -> libc::uid_t {
        self.uid
    }

    pub fn gid(self) -> libc::gid_t {
        self.gid
    }

    pub(crate) async fn assign_to(self, run_dir: &Path) -> Result<()> {
        let run_dir = run_dir.to_path_buf();
        tokio::task::spawn_blocking(move || assign_tree(&run_dir, self))
            .await
            .context("recording artifact ownership task failed")?
    }
}

impl fmt::Display for ArtifactOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.uid, self.gid)
    }
}

impl FromStr for ArtifactOwner {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let Some((uid, gid)) = value.split_once(':') else {
            return Err(owner_format_error());
        };
        if uid.is_empty()
            || gid.is_empty()
            || !uid.bytes().all(|byte| byte.is_ascii_digit())
            || !gid.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(owner_format_error());
        }
        let uid = uid.parse().map_err(|_| owner_format_error())?;
        let gid = gid.parse().map_err(|_| owner_format_error())?;
        Ok(Self { uid, gid })
    }
}

fn owner_format_error() -> String {
    "artifact owner must use numeric UID:GID".to_string()
}

fn assign_tree(path: &Path, owner: ArtifactOwner) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect recording artifact {}", path.display()))?;
    if metadata.file_type().is_dir() {
        for child in fs::read_dir(path)
            .with_context(|| format!("failed to list recording artifact dir {}", path.display()))?
        {
            let child = child.with_context(|| {
                format!(
                    "failed to read recording artifact entry under {}",
                    path.display()
                )
            })?;
            assign_tree(&child.path(), owner)?;
        }
    }
    assign_path(path, owner)
}

fn assign_path(path: &Path, owner: ArtifactOwner) -> Result<()> {
    let path_bytes = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("recording artifact path contains NUL: {}", path.display()))?;
    let result = unsafe { libc::lchown(path_bytes.as_ptr(), owner.uid, owner.gid) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    bail!(
        "failed to assign recording artifact {} to {}: {}",
        path.display(),
        owner,
        error
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[test]
    fn parses_only_numeric_uid_gid_pairs() {
        let owner = "1114:1115".parse::<ArtifactOwner>().unwrap();

        assert_eq!(owner.uid(), 1114);
        assert_eq!(owner.gid(), 1115);
        assert_eq!(owner.to_string(), "1114:1115");

        for invalid in ["", "1114", ":1115", "1114:", "-1:1115", "1114:1:2"] {
            assert!(invalid.parse::<ArtifactOwner>().is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn assigns_the_complete_tree_to_the_requested_owner() {
        let temporary = tempfile::tempdir().unwrap();
        let nested = temporary.path().join("group/case");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("request.json"), "{}\n").unwrap();
        let owner = ArtifactOwner::new(unsafe { libc::geteuid() }, unsafe { libc::getegid() });

        owner.assign_to(temporary.path()).await.unwrap();

        for path in [
            temporary.path().to_path_buf(),
            temporary.path().join("group"),
            nested.clone(),
            nested.join("request.json"),
        ] {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.uid(), owner.uid());
            assert_eq!(metadata.gid(), owner.gid());
        }
    }
}
