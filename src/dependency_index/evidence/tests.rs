use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("run");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("recording-run.json"),
        json!({"run_id":"run","status":"completed"}).to_string(),
    )
    .unwrap();
    add_case(&root, "first");
    (temp, root)
}
fn add_case(root: &Path, id: &str) {
    let dir = root.join("apis/api").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("dependencies.jsonl"), "\n").unwrap();
    fs::write(dir.join("request.json"), "{}").unwrap();
    fs::write(dir.join("expected-response.json"), "{}").unwrap();
}

#[test]
fn source_catalog_reuses_sealed_content_and_detects_membership_and_byte_changes() {
    let (_temp, root) = fixture();
    let sealed = seal(&root).unwrap();
    assert!(sealed.is_file());
    let first = prepare(&root).unwrap();
    let before = HASHED_BYTES.get();
    let reused = prepare(&root).unwrap();
    assert_eq!(first, reused);
    assert_eq!(HASHED_BYTES.get(), before);
    let expected = root.join("apis/api/first/expected-response.json");
    fs::write(&expected, "[]").unwrap(); // Same size, different content and ctime.
    let changed = prepare(&root).unwrap();
    assert_ne!(changed.digest, first.digest);
    add_case(&root, "second");
    let added = prepare(&root).unwrap();
    assert_ne!(added, changed);
    assert_eq!(added.files, 7);
    fs::remove_file(expected).unwrap();
    assert!(prepare(&root).is_err());
}

#[test]
fn source_catalog_rejects_symlinks_and_ignores_corrupt_derived_catalogs() {
    let (_temp, root) = fixture();
    let first = prepare(&root).unwrap();
    fs::write(&first.path, "broken").unwrap();
    let restored = prepare(&root).unwrap();
    assert_eq!(first.digest, restored.digest);
    let original = root.join("apis/api/first/request.json");
    let target = root.join("moved.json");
    fs::rename(&original, &target).unwrap();
    std::os::unix::fs::symlink(target, &original).unwrap();
    assert!(prepare(&root).is_err());
}

#[test]
fn source_catalog_has_no_batch_byte_cap_and_warm_lookup_reads_no_original_payload() {
    let (_temp, root) = fixture();
    // Sparse content exercises byte accounting without allocating or writing a
    // 513 MiB in-memory fixture. Content identity is verified once, then reused.
    let large = root.join("apis/api/first/expected-response.json");
    fs::File::options()
        .write(true)
        .open(&large)
        .unwrap()
        .set_len(513 * 1024 * 1024)
        .unwrap();
    let first = prepare(&root).unwrap();
    let before = HASHED_BYTES.get();
    assert_eq!(prepare(&root).unwrap(), first);
    assert_eq!(HASHED_BYTES.get(), before);
    assert!(fs::metadata(first.path).unwrap().len() < 4096);
}
