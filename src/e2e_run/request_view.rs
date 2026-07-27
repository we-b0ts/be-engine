use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use uuid::Uuid;

use crate::request_headers::decrypt_request_file;

pub(super) struct RequestCaseView {
    case_dir: PathBuf,
    cleanup_root: Option<PathBuf>,
}

impl RequestCaseView {
    pub(super) fn prepare(case_dir: &Path, temporary_root: &Path) -> Result<Self> {
        let request_path = case_dir.join("request.json");
        let Some(decrypted_request) = decrypt_request_file(&request_path)? else {
            return Ok(Self {
                case_dir: case_dir.to_path_buf(),
                cleanup_root: None,
            });
        };
        Self::materialize(case_dir, temporary_root, &decrypted_request)
    }

    pub(super) fn case_dir(&self) -> &Path {
        &self.case_dir
    }

    fn materialize(
        case_dir: &Path,
        temporary_root: &Path,
        decrypted_request: &[u8],
    ) -> Result<Self> {
        let source = fs::canonicalize(case_dir)
            .with_context(|| format!("failed to resolve case directory {}", case_dir.display()))?;
        let case_name = source
            .file_name()
            .context("case directory has no final path component")?;
        let cleanup_root = temporary_root
            .join("decrypted-request-views")
            .join(Uuid::new_v4().to_string());
        let view = cleanup_root.join(case_name);
        let result = (|| {
            fs::create_dir_all(&view).with_context(|| {
                format!("failed to create decrypted request view {}", view.display())
            })?;
            fs::set_permissions(&cleanup_root, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&view, fs::Permissions::from_mode(0o700))?;
            for entry in fs::read_dir(&source)
                .with_context(|| format!("failed to scan case directory {}", source.display()))?
            {
                let entry = entry.with_context(|| {
                    format!(
                        "failed to read case directory entry under {}",
                        source.display()
                    )
                })?;
                if entry.file_name() == "request.json" {
                    continue;
                }
                symlink(entry.path(), view.join(entry.file_name())).with_context(|| {
                    format!(
                        "failed to link case artifact {} into decrypted request view",
                        entry.path().display()
                    )
                })?;
            }
            let request_path = view.join("request.json");
            let mut request = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&request_path)
                .with_context(|| {
                    format!(
                        "failed to create decrypted request file {}",
                        request_path.display()
                    )
                })?;
            request
                .write_all(decrypted_request)
                .context("failed to write decrypted request view")?;
            ensure!(
                request.metadata()?.permissions().mode() & 0o777 == 0o600,
                "decrypted request view permissions are not 0600"
            );
            Ok(Self {
                case_dir: view,
                cleanup_root: Some(cleanup_root.clone()),
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&cleanup_root);
        }
        result
    }
}

impl Drop for RequestCaseView {
    fn drop(&mut self) {
        if let Some(root) = &self.cleanup_root {
            let _ = fs::remove_dir_all(root);
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn materializes_a_private_short_lived_case_view() {
        let temp = tempdir().unwrap();
        let case = temp.path().join("case-id");
        fs::create_dir(&case).unwrap();
        fs::write(case.join("request.json"), "{}").unwrap();
        fs::write(case.join("expected-response.json"), "{}").unwrap();

        let view =
            RequestCaseView::materialize(&case, temp.path(), br#"{"method":"GET"}"#).unwrap();
        let view_dir = view.case_dir().to_path_buf();

        assert_eq!(view_dir.file_name().unwrap(), "case-id");
        assert_eq!(
            fs::read_to_string(view_dir.join("request.json")).unwrap(),
            r#"{"method":"GET"}"#
        );
        assert_eq!(
            fs::metadata(view_dir.join("request.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(view_dir.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&view_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::read_to_string(view_dir.join("expected-response.json")).unwrap(),
            "{}"
        );

        drop(view);
        assert!(!view_dir.exists());
    }
}
