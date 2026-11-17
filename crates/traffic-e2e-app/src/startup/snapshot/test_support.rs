use super::*;

/// Publish a valid snapshot manifest for files already installed by a fixture.
pub(crate) fn install_startup_snapshot(root: &Path, mounts: Vec<StartupSnapshotMount>) {
    let mounts_root = root.join(crate::repository::LOCAL_STARTUP_MOUNTS_ROOT);
    fs::create_dir_all(&mounts_root).unwrap();
    let manifest = StartupManifest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        snapshot_id: "startup-test".into(),
        content_revision: snapshot_content_revision(&mounts_root).unwrap(),
        source_snapshot_id: "source-test".into(),
        source_image_id: "image-test".into(),
        mounts,
    };
    write_json(
        &root.join(crate::repository::LOCAL_STARTUP_MANIFEST_PATH),
        &manifest,
        0o600,
    )
    .unwrap();
}
