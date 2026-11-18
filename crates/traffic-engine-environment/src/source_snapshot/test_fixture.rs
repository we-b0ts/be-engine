//! A complete local fixture using the snapshot owner's real digest and loader.
use super::*;

pub fn install(target_root: &Path) -> String {
    let root = target_root.join(crate::repository::LOCAL_SOURCE_ROOT);
    fs::create_dir_all(root.join("mounts")).unwrap();
    let image_id = format!("sha256:{}", "1".repeat(64));
    let runtime = SourceRuntime {
        image_entrypoint: Vec::new(),
        image_command: vec!["/app/source".into()],
        working_directory: Some("/app".into()),
        image_user: None,
        pod_command: None,
        pod_args: None,
        security: SourceSecurityContext::default(),
        environment: BTreeMap::new(),
        target_environment: BTreeSet::new(),
    };
    write_json(&root.join("runtime.json"), &runtime).unwrap();
    let mut manifest = SourceSnapshotManifest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        snapshot_id: "source-fixture".into(),
        content_revision: String::new(),
        provider: SourceProviderEvidence::DockerContainer {
            container: "source-fixture".into(),
            container_id: "2".repeat(64),
            source_image_id: image_id.clone(),
            restart_count: 0,
        },
        image: SourceImage {
            reference: "source-fixture:latest".into(),
            registry_digest: Some(format!("source-fixture@sha256:{}", "1".repeat(64))),
            archive_sha256: None,
            local_id: image_id,
            architecture: "amd64".into(),
            os: "linux".into(),
        },
        mounts: Vec::new(),
        ignored_mounts: Vec::new(),
    };
    manifest.content_revision = snapshot_content_revision(
        &root,
        &manifest.provider,
        &manifest.image,
        &manifest.mounts,
        &manifest.ignored_mounts,
    )
    .unwrap();
    write_json(&root.join("manifest.json"), &manifest).unwrap();
    source_image_revision(target_root).unwrap()
}
