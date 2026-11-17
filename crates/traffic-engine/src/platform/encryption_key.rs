use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

pub(crate) fn load_or_create(target_root: &Path) -> Result<String> {
    let supplied = match std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!(
                "{} must contain valid UTF-8",
                crate::request_headers::ENCRYPTION_KEY_ENV
            )
        }
    };
    load_or_create_with(target_root, supplied.as_deref())
}

fn load_or_create_with(target_root: &Path, supplied: Option<&str>) -> Result<String> {
    if let Some(supplied) = supplied {
        crate::request_headers::validate_encryption_key(supplied)?;
    }
    let secrets_root = target_root.join(crate::repository::LOCAL_SECRETS_ROOT);
    ensure_private_directory(&secrets_root)?;
    let key_path = target_root.join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH);
    let owner = crate::ArtifactOwner::invoking()?;

    let key = match fs::symlink_metadata(&key_path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "managed request-header encryption key must be a regular file and not a symlink: {}",
                key_path.display()
            );
            let stored = fs::read_to_string(&key_path).with_context(|| {
                format!(
                    "failed to read managed request-header encryption key {}",
                    key_path.display()
                )
            })?;
            crate::request_headers::validate_encryption_key(&stored)?;
            if let Some(supplied) = supplied {
                ensure!(
                    stored == supplied,
                    "{} conflicts with the managed project encryption key {}",
                    crate::request_headers::ENCRYPTION_KEY_ENV,
                    key_path.display()
                );
            }
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).with_context(
                || {
                    format!(
                        "failed to protect managed encryption key {}",
                        key_path.display()
                    )
                },
            )?;
            stored
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = match supplied {
                Some(value) => value.to_string(),
                None => crate::request_headers::generate_encryption_key()?,
            };
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .with_context(|| {
                    format!(
                        "failed to create managed request-header encryption key {}",
                        key_path.display()
                    )
                })?;
            file.write_all(key.as_bytes())?;
            file.sync_all()?;
            key
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect managed request-header encryption key {}",
                    key_path.display()
                )
            });
        }
    };
    owner.assign_path_to(&secrets_root)?;
    owner.assign_path_to(&key_path)?;
    Ok(key)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "managed secrets root must be a directory and not a symlink: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(0o700)
                .create(path)
                .with_context(|| {
                    format!("failed to create managed secrets root {}", path.display())
                })?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect managed secrets root {}", path.display())
            });
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to protect managed secrets root {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    #[test]
    fn creates_reuses_and_protects_one_project_key() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir(target.path().join(crate::repository::TRAFFIC_E2E_ROOT)).unwrap();
        fs::create_dir(target.path().join(crate::repository::LOCAL_ROOT)).unwrap();

        let first = load_or_create_with(target.path(), None).unwrap();
        let second = load_or_create_with(target.path(), None).unwrap();
        let key_path = target
            .path()
            .join(crate::repository::LOCAL_ENCRYPTION_KEY_PATH);

        assert_eq!(first, second);
        assert_eq!(STANDARD.decode(&first).unwrap().len(), 32);
        assert_eq!(fs::metadata(&key_path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(key_path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&key_path).unwrap().uid(), unsafe {
            libc::geteuid()
        });
    }

    #[test]
    fn imports_one_compatible_override_and_rejects_a_later_conflict() {
        let target = tempfile::tempdir().unwrap();
        fs::create_dir(target.path().join(crate::repository::TRAFFIC_E2E_ROOT)).unwrap();
        fs::create_dir(target.path().join(crate::repository::LOCAL_ROOT)).unwrap();
        let imported = STANDARD.encode([7_u8; 32]);
        let conflicting = STANDARD.encode([8_u8; 32]);

        assert_eq!(
            load_or_create_with(target.path(), Some(&imported)).unwrap(),
            imported
        );
        let error = load_or_create_with(target.path(), Some(&conflicting)).unwrap_err();
        assert!(error.to_string().contains("conflicts"));
    }
}
