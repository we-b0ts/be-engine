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

pub(crate) fn create_many_atomic(files: &[(std::path::PathBuf, Vec<u8>)]) -> Result<()> {
    anyhow::ensure!(
        !files.is_empty(),
        "atomic configuration set must not be empty"
    );
    for (path, _) in files {
        match fs::symlink_metadata(path) {
            Ok(_) => anyhow::bail!(
                "{} already exists; refusing to initialize any configuration",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
    }

    let mut reserved = Vec::with_capacity(files.len());
    for (path, contents) in files {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if let Err(error) = fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))
        {
            for (temporary, _) in &reserved {
                let _ = fs::remove_file(temporary);
            }
            return Err(error);
        }
        let (temporary_path, mut file) = match reserve_temporary(path) {
            Ok(reserved_file) => reserved_file,
            Err(error) => {
                for (temporary, _) in &reserved {
                    let _ = fs::remove_file(temporary);
                }
                return Err(error);
            }
        };
        let write_result = (|| -> Result<()> {
            file.write_all(contents)
                .context("failed to write temporary config file")?;
            file.sync_all()
                .context("failed to sync temporary config file")?;
            Ok(())
        })();
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary_path);
            for (temporary, _) in &reserved {
                let _ = fs::remove_file(temporary);
            }
            return Err(error);
        }
        reserved.push((temporary_path, path.clone()));
    }

    let mut published = Vec::with_capacity(files.len());
    let publish_result = (|| -> Result<()> {
        for (temporary, target) in &reserved {
            fs::hard_link(temporary, target)
                .with_context(|| format!("failed to publish new config {}", target.display()))?;
            published.push(target.clone());
        }
        for (temporary, _) in &reserved {
            fs::remove_file(temporary).context("failed to remove temporary config link")?;
        }
        let mut parents = files
            .iter()
            .filter_map(|(path, _)| path.parent())
            .collect::<Vec<_>>();
        parents.sort_unstable();
        parents.dedup();
        for parent in parents {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("failed to sync config directory {}", parent.display()))?;
        }
        Ok(())
    })();
    if let Err(error) = publish_result {
        for target in published {
            let _ = fs::remove_file(target);
        }
        for (temporary, _) in reserved {
            let _ = fs::remove_file(temporary);
        }
        return Err(error).context("configuration set was rolled back");
    }
    Ok(())
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

pub(crate) fn write_many_atomic(files: &[(std::path::PathBuf, Vec<u8>)]) -> Result<()> {
    anyhow::ensure!(
        !files.is_empty(),
        "configuration update set must not be empty"
    );
    let mut unique = std::collections::BTreeSet::new();
    let mut staged = Vec::with_capacity(files.len());
    for (path, contents) in files {
        anyhow::ensure!(
            unique.insert(path.clone()),
            "duplicate configuration target {}",
            path.display()
        );
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect config {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "{} must be a regular file and not a symlink",
            path.display()
        );
        let (temporary, mut file) = reserve_temporary(path)?;
        let stage_result = (|| -> Result<()> {
            file.write_all(contents)
                .context("failed to write temporary config file")?;
            file.sync_all()
                .context("failed to sync temporary config file")?;
            drop(file);
            fs::set_permissions(&temporary, metadata.permissions())
                .context("failed to preserve config permissions")?;
            Ok(())
        })();
        if let Err(error) = stage_result {
            let _ = fs::remove_file(&temporary);
            for (temporary, _) in staged {
                let _ = fs::remove_file(temporary);
            }
            return Err(error);
        }
        staged.push((temporary, path.clone()));
    }

    let mut backups = Vec::with_capacity(files.len());
    for (_, target) in &staged {
        match reserve_backup(target) {
            Ok(backup) => backups.push((backup, target.clone())),
            Err(error) => {
                for (backup, _) in backups {
                    let _ = fs::remove_file(backup);
                }
                for (temporary, _) in staged {
                    let _ = fs::remove_file(temporary);
                }
                return Err(error);
            }
        }
    }

    let publish_result = (|| -> Result<()> {
        for (temporary, target) in &staged {
            fs::rename(temporary, target).with_context(|| {
                format!("failed to atomically replace config {}", target.display())
            })?;
        }
        sync_parents(files)?;
        Ok(())
    })();
    if let Err(error) = publish_result {
        let mut rollback_errors = Vec::new();
        for (backup, target) in &backups {
            if let Err(rollback) = fs::rename(backup, target) {
                rollback_errors.push(format!("{}: {rollback}", target.display()));
            }
        }
        for (temporary, _) in &staged {
            let _ = fs::remove_file(temporary);
        }
        if rollback_errors.is_empty() {
            return Err(error).context("configuration update set was rolled back");
        }
        anyhow::bail!(
            "configuration update failed ({error:#}) and rollback was incomplete: {}",
            rollback_errors.join("; ")
        );
    }

    for (backup, _) in backups {
        fs::remove_file(&backup)
            .with_context(|| format!("failed to remove config backup {}", backup.display()))?;
    }
    sync_parents(files)?;
    Ok(())
}

fn sync_parents(files: &[(std::path::PathBuf, Vec<u8>)]) -> Result<()> {
    let mut parents = files
        .iter()
        .map(|(path, _)| path.parent().unwrap_or_else(|| Path::new(".")))
        .collect::<Vec<_>>();
    parents.sort_unstable();
    parents.dedup();
    for parent in parents {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("failed to sync config directory {}", parent.display()))?;
    }
    Ok(())
}

fn reserve_backup(path: &Path) -> Result<std::path::PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("config path must have a file name")?
        .to_string_lossy();
    for attempt in 0..100 {
        let candidate = parent.join(format!(
            ".{file_name}.backup.{}.{}",
            std::process::id(),
            attempt
        ));
        match fs::hard_link(path, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create config rollback link"),
        }
    }
    anyhow::bail!("failed to reserve config rollback link")
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

    #[test]
    fn create_many_atomic_refuses_the_entire_set_when_one_target_exists() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.yaml");
        let second = directory.path().join("second.toml");
        fs::write(&second, "existing\n").unwrap();

        let error = create_many_atomic(&[
            (first.clone(), b"first\n".to_vec()),
            (second.clone(), b"second\n".to_vec()),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("refusing to initialize any"));
        assert!(!first.exists());
        assert_eq!(fs::read_to_string(second).unwrap(), "existing\n");
    }

    #[test]
    fn write_many_atomic_replaces_an_existing_set() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.yaml");
        let second = directory.path().join("second.toml");
        fs::write(&first, "old first\n").unwrap();
        fs::write(&second, "old second\n").unwrap();

        write_many_atomic(&[
            (first.clone(), b"new first\n".to_vec()),
            (second.clone(), b"new second\n".to_vec()),
        ])
        .unwrap();

        assert_eq!(fs::read_to_string(first).unwrap(), "new first\n");
        assert_eq!(fs::read_to_string(second).unwrap(), "new second\n");
        assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("backup")
        }));
    }

    #[test]
    fn write_many_atomic_rejects_symlinks_before_writing() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let first = directory.path().join("first.yaml");
        let actual = directory.path().join("actual.toml");
        let linked = directory.path().join("linked.toml");
        fs::write(&first, "old first\n").unwrap();
        fs::write(&actual, "old actual\n").unwrap();
        symlink(&actual, &linked).unwrap();

        let error = write_many_atomic(&[
            (first.clone(), b"new first\n".to_vec()),
            (linked, b"new linked\n".to_vec()),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("must be a regular file"));
        assert_eq!(fs::read_to_string(first).unwrap(), "old first\n");
        assert_eq!(fs::read_to_string(actual).unwrap(), "old actual\n");
    }
}
