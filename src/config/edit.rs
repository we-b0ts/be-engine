use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};

pub(crate) fn create_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    match fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("{} already exists; refusing to replace it", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let (temporary_path, mut file) = reserve_temporary(path)?;

    let result = (|| -> Result<()> {
        file.write_all(contents)
            .context("failed to write temporary config file")?;
        file.sync_all()
            .context("failed to sync temporary config file")?;
        drop(file);
        fs::hard_link(&temporary_path, path)
            .with_context(|| format!("failed to publish new config {}", path.display()))?;
        fs::remove_file(&temporary_path).context("failed to remove temporary config link")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("failed to sync config directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect config {}", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let (temporary_path, mut file) = reserve_temporary(path)?;

    let result = (|| -> Result<()> {
        file.write_all(contents)
            .context("failed to write temporary config file")?;
        file.sync_all()
            .context("failed to sync temporary config file")?;
        drop(file);
        fs::set_permissions(&temporary_path, metadata.permissions())
            .context("failed to preserve config permissions")?;
        fs::rename(&temporary_path, path)
            .with_context(|| format!("failed to atomically replace config {}", path.display()))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("failed to sync config directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn reserve_temporary(path: &Path) -> Result<(std::path::PathBuf, File)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("config path must have a file name")?
        .to_string_lossy();

    for attempt in 0..100 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create temporary config file"),
        }
    }
    anyhow::bail!("failed to reserve temporary config file")
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn create_atomic_publishes_once_without_replacing() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/config.toml");

        create_atomic(&path, b"first\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");

        let error = create_atomic(&path, b"second\n").unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
    }
}
