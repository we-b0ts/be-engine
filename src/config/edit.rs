use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};

pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect recorder config {}", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("recorder config path must have a file name")?
        .to_string_lossy();

    let mut temporary = None;
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
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create temporary config file"),
        }
    }
    let (temporary_path, mut file) =
        temporary.context("failed to reserve temporary config file")?;

    let result = (|| -> Result<()> {
        file.write_all(contents)
            .context("failed to write temporary config file")?;
        file.sync_all()
            .context("failed to sync temporary config file")?;
        drop(file);
        fs::set_permissions(&temporary_path, metadata.permissions())
            .context("failed to preserve recorder config permissions")?;
        fs::rename(&temporary_path, path).with_context(|| {
            format!(
                "failed to atomically replace recorder config {}",
                path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("failed to sync recorder config directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}
