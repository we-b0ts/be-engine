use super::*;

#[test]
fn discovers_only_global_dependency_files() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("api").join("case");
    std::fs::create_dir_all(&case_dir).unwrap();
    for filename in [
        "global-dependencies.jsonl",
        "global-dependencies-debug.jsonl",
    ] {
        std::fs::write(temp.path().join(filename), "").unwrap();
    }

    let (semantic, debug) = find_run_level_dependencies(&case_dir);

    assert_eq!(
        semantic.unwrap(),
        temp.path().join("global-dependencies.jsonl")
    );
    assert_eq!(
        debug.unwrap(),
        temp.path().join("global-dependencies-debug.jsonl")
    );
}

#[test]
fn does_not_load_legacy_bootstrap_dependency_files() {
    let temp = tempfile::tempdir().unwrap();
    let case_dir = temp.path().join("api").join("case");
    std::fs::create_dir_all(&case_dir).unwrap();
    std::fs::write(temp.path().join("bootstrap-dependencies.jsonl"), "").unwrap();
    std::fs::write(temp.path().join("bootstrap-dependencies-debug.jsonl"), "").unwrap();

    assert_eq!(find_run_level_dependencies(&case_dir), (None, None));
}
