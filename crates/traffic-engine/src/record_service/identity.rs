//! Snapshot only the resolved Source entrypoint file, never infer a build closure.
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::dependency::observation::SourceArtifactIdentity;

pub(super) async fn register(
    state: &crate::AppState,
    program: &Path,
    directory: &Path,
) -> Result<()> {
    let program = program.to_owned();
    let directory = directory.to_owned();
    let identity = tokio::task::spawn_blocking(move || snapshot(&program, &directory))
        .await
        .context("Source entrypoint fingerprint task failed")?;
    state
        .recorder()
        .set_source_artifact_identity(identity)
        .await
}

fn snapshot(program: &Path, directory: &Path) -> SourceArtifactIdentity {
    match fingerprint(program, directory) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(path=%program.display(), %error, "Source entrypoint file identity unavailable");
            SourceArtifactIdentity::Unavailable {
                reason: format!("entrypoint_file_identity_unavailable: {error:#}"),
            }
        }
    }
}

fn fingerprint(program: &Path, directory: &Path) -> Result<SourceArtifactIdentity> {
    let mut file = File::open(program).context("could not read resolved Source entrypoint")?;
    let before = file.metadata()?;
    ensure!(
        before.is_file(),
        "resolved Source entrypoint is not a regular file"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        stamp(&before) == stamp(&file.metadata()?)
            && stamp(&before) == stamp(&std::fs::metadata(program)?),
        "resolved Source entrypoint changed while fingerprinting"
    );
    Ok(SourceArtifactIdentity::EntrypointFile {
        sha256: format!("{:x}", hash.finalize()),
        path: program.to_string_lossy().into_owned(),
        working_directory: Some(
            std::fs::canonicalize(directory)
                .unwrap_or_else(|_| PathBuf::from(directory))
                .to_string_lossy()
                .into_owned(),
        ),
    })
}

fn stamp(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrypoint_identity_hashes_real_file_bytes_without_claiming_a_build_closure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source-entrypoint");
        std::fs::write(&path, b"abc").unwrap();
        let identity = snapshot(&path, temp.path());
        let SourceArtifactIdentity::EntrypointFile {
            sha256,
            path: captured,
            working_directory,
        } = &identity
        else {
            panic!("real entrypoint must have a content identity")
        };
        assert_eq!(
            sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(captured, path.to_str().unwrap());
        assert_eq!(working_directory.as_deref(), temp.path().to_str());
        assert_eq!(
            serde_json::to_value(identity).unwrap()["status"],
            "entrypoint_file"
        );
    }

    #[test]
    fn unreadable_entrypoint_identity_is_explicitly_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            matches!(snapshot(&temp.path().join("missing"), temp.path()), SourceArtifactIdentity::Unavailable { reason } if reason.contains("entrypoint_file_identity_unavailable"))
        );
    }
}
