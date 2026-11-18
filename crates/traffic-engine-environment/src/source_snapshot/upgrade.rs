use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use uuid::Uuid;

use super::{
    KubernetesSourceOptions, PRIVATE_DIRECTORY_MODE, SNAPSHOT_SCHEMA_VERSION,
    SourceSnapshotManifest, SourceSnapshotReport,
};

pub struct SourceSnapshotUpgradeGuard {
    target_root: PathBuf,
    previous: PathBuf,
    previous_snapshot_id: String,
    previous_image_id: String,
    report: Option<SourceSnapshotReport>,
    armed: bool,
}

struct CapturedUpgrade {
    report: SourceSnapshotReport,
    content_revision: String,
}

pub fn begin_kubernetes_source_snapshot_upgrade(
    target_root: &Path,
    options: &KubernetesSourceOptions,
) -> Result<SourceSnapshotUpgradeGuard> {
    let target_root = fs::canonicalize(target_root)
        .with_context(|| format!("failed to resolve target root {}", target_root.display()))?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let current = super::load(&target_root)?;
    let previous_snapshot_id = current.manifest.snapshot_id.clone();
    let previous_image_id = current.manifest.image.local_id.clone();
    let previous_content_revision = current.manifest.content_revision.clone();

    let local_root = target_root.join(crate::repository::LOCAL_ROOT);
    fs::create_dir_all(&local_root)
        .with_context(|| format!("failed to create {}", local_root.display()))?;
    fs::set_permissions(
        &local_root,
        fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
    )?;
    let snapshot_id = Uuid::new_v4().simple().to_string();
    let staging = local_root.join(format!(".source-{snapshot_id}.staging"));
    ensure!(
        !staging.exists(),
        "source upgrade staging path already exists"
    );
    fs::create_dir(&staging).context("failed to create source upgrade staging directory")?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;

    let captured = match capture_staging(&staging, options, snapshot_id) {
        Ok(captured) => captured,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    let result = publish_staging(
        target_root,
        staging.clone(),
        captured,
        &previous_snapshot_id,
        &previous_image_id,
        &previous_content_revision,
    );
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(staging);
    }
    result
}

fn capture_staging(
    staging: &Path,
    options: &KubernetesSourceOptions,
    snapshot_id: String,
) -> Result<CapturedUpgrade> {
    let mounts_root = staging.join("mounts");
    fs::create_dir(&mounts_root).context("failed to create source mount snapshot root")?;
    let captured = super::kubernetes::capture(options, &mounts_root)?;
    super::write_json(&staging.join("runtime.json"), &captured.runtime)?;
    let content_revision = super::snapshot_content_revision(
        staging,
        &captured.provider,
        &captured.image,
        &captured.mounts,
        &captured.ignored_mounts,
    )?;
    let manifest = SourceSnapshotManifest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        snapshot_id,
        content_revision: content_revision.clone(),
        provider: captured.provider,
        image: captured.image,
        mounts: captured.mounts,
        ignored_mounts: captured.ignored_mounts,
    };
    super::write_json(&staging.join("manifest.json"), &manifest)?;
    let snapshot = super::load_root(staging).context("captured source upgrade is invalid")?;
    Ok(CapturedUpgrade {
        report: super::snapshot_report("upgraded", snapshot),
        content_revision,
    })
}

fn publish_staging(
    target_root: PathBuf,
    staging: PathBuf,
    captured: CapturedUpgrade,
    previous_snapshot_id: &str,
    previous_image_id: &str,
    previous_content_revision: &str,
) -> Result<SourceSnapshotUpgradeGuard> {
    let report = captured.report;
    ensure!(
        report.snapshot_id != previous_snapshot_id,
        "source upgrade must allocate a new snapshot ID"
    );
    ensure!(
        captured.content_revision != previous_content_revision,
        "source snapshot content did not change; refusing a no-op source upgrade"
    );
    let source = target_root.join(crate::repository::LOCAL_SOURCE_ROOT);
    let local_root = source.parent().expect("source snapshot has a parent");
    let previous = local_root.join(format!(".source-{}.previous", report.snapshot_id));
    ensure!(
        !previous.exists(),
        "source upgrade backup path already exists"
    );
    fs::rename(&source, &previous).context("failed to preserve previous source snapshot")?;
    if let Err(error) = fs::rename(&staging, &source) {
        let _ = fs::rename(&previous, &source);
        return Err(error).context("failed to publish upgraded source snapshot");
    }
    if let Err(error) = File::open(local_root).and_then(|directory| directory.sync_all()) {
        return match rollback_paths(&source, &previous) {
            Ok(()) => Err(error).context("failed to sync upgraded source snapshot"),
            Err(rollback_error) => Err(error).context(format!(
                "failed to sync upgraded source snapshot and rollback also failed: {rollback_error:#}"
            )),
        };
    }
    Ok(SourceSnapshotUpgradeGuard {
        target_root,
        previous,
        previous_snapshot_id: previous_snapshot_id.to_string(),
        previous_image_id: previous_image_id.to_string(),
        report: Some(report),
        armed: true,
    })
}

fn rollback_paths(source: &Path, previous: &Path) -> Result<()> {
    let discarded = previous.with_extension("discarded");
    ensure!(
        !discarded.exists(),
        "source upgrade rollback path already exists: {}",
        discarded.display()
    );
    if source.exists() {
        fs::rename(source, &discarded)
            .context("failed to preserve rejected source snapshot during rollback")?;
    }
    if let Err(error) = fs::rename(previous, source) {
        if discarded.exists() {
            let _ = fs::rename(&discarded, source);
        }
        return Err(error).context("failed to restore previous source snapshot");
    }
    if discarded.exists() {
        let _ = fs::remove_dir_all(discarded);
    }
    if let Some(local_root) = source.parent() {
        File::open(local_root)?.sync_all()?;
    }
    Ok(())
}

impl SourceSnapshotUpgradeGuard {
    pub fn previous_snapshot_id(&self) -> &str {
        &self.previous_snapshot_id
    }

    pub fn previous_image_id(&self) -> &str {
        &self.previous_image_id
    }

    pub fn commit(mut self) -> SourceSnapshotReport {
        self.armed = false;
        if self.previous.exists() {
            let _ = fs::remove_dir_all(&self.previous);
        }
        self.report.take().expect("source upgrade report exists")
    }

    pub fn rollback(mut self) -> Result<()> {
        let source = self.target_root.join(crate::repository::LOCAL_SOURCE_ROOT);
        rollback_paths(&source, &self.previous)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for SourceSnapshotUpgradeGuard {
    fn drop(&mut self) {
        if self.armed {
            let source = self.target_root.join(crate::repository::LOCAL_SOURCE_ROOT);
            let _ = rollback_paths(&source, &self.previous);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceImage, SourceProviderEvidence};

    fn report(snapshot_id: &str, image_id: &str) -> SourceSnapshotReport {
        SourceSnapshotReport {
            status: "upgraded",
            snapshot_id: snapshot_id.to_string(),
            root: PathBuf::from(crate::repository::LOCAL_SOURCE_ROOT),
            provider: SourceProviderEvidence::KubernetesPod {
                context: None,
                namespace: "default".to_string(),
                pod: "source-new".to_string(),
                pod_uid: "new-uid".to_string(),
                container: "app".to_string(),
                restart_count: 0,
            },
            image: SourceImage {
                reference: "example/source:2".to_string(),
                registry_digest: Some(format!("example/source@sha256:{}", "b".repeat(64))),
                archive_sha256: None,
                local_id: image_id.to_string(),
                architecture: "amd64".to_string(),
                os: "linux".to_string(),
            },
            environment_variables: 2,
            target_environment_variables: 1,
            mounts: Vec::new(),
            ignored_mounts: Vec::new(),
        }
    }

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let target = tempfile::tempdir().unwrap();
        let local = target.path().join(crate::repository::LOCAL_ROOT);
        let source = target.path().join(crate::repository::LOCAL_SOURCE_ROOT);
        let staging = local.join("candidate");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("marker"), "old").unwrap();
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("marker"), "new").unwrap();
        (target, staging)
    }

    #[test]
    fn dropping_upgrade_restores_previous_snapshot() {
        let (target, staging) = fixture();
        let guard = publish_staging(
            target.path().to_path_buf(),
            staging,
            CapturedUpgrade {
                report: report("new", &format!("sha256:{}", "b".repeat(64))),
                content_revision: "new-content".to_string(),
            },
            "old",
            &format!("sha256:{}", "a".repeat(64)),
            "old-content",
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(
                target
                    .path()
                    .join(crate::repository::LOCAL_SOURCE_ROOT)
                    .join("marker")
            )
            .unwrap(),
            "new"
        );
        drop(guard);
        assert_eq!(
            fs::read_to_string(
                target
                    .path()
                    .join(crate::repository::LOCAL_SOURCE_ROOT)
                    .join("marker")
            )
            .unwrap(),
            "old"
        );
    }

    #[test]
    fn committing_runtime_only_upgrade_keeps_new_snapshot() {
        let (target, staging) = fixture();
        let unchanged_image = format!("sha256:{}", "a".repeat(64));
        let guard = publish_staging(
            target.path().to_path_buf(),
            staging,
            CapturedUpgrade {
                report: report("new", &unchanged_image),
                content_revision: "new-content".to_string(),
            },
            "old",
            &unchanged_image,
            "old-content",
        )
        .unwrap();
        let committed = guard.commit();
        assert_eq!(committed.snapshot_id, "new");
        assert_eq!(
            fs::read_to_string(
                target
                    .path()
                    .join(crate::repository::LOCAL_SOURCE_ROOT)
                    .join("marker")
            )
            .unwrap(),
            "new"
        );
    }

    #[test]
    fn unchanged_source_content_is_rejected_before_replacement() {
        let (target, staging) = fixture();
        let image_id = format!("sha256:{}", "a".repeat(64));
        let error = publish_staging(
            target.path().to_path_buf(),
            staging,
            CapturedUpgrade {
                report: report("new", &image_id),
                content_revision: "old-content".to_string(),
            },
            "old",
            &image_id,
            "old-content",
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("did not change"));
        assert_eq!(
            fs::read_to_string(
                target
                    .path()
                    .join(crate::repository::LOCAL_SOURCE_ROOT)
                    .join("marker")
            )
            .unwrap(),
            "old"
        );
    }
}
