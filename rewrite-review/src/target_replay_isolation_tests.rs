use super::*;
use std::{fs, process::Command};

fn inspect(target: &Path, pr_base: &str) -> Result<ReplayIsolationReport> {
    Ok(inspect_added(crate::source_diff::added_rust_lines(
        target, pr_base,
    )?))
}

#[test]
fn persisted_report_cannot_pass_with_remaining_violations_or_an_obsolete_schema() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::write(
        target.path().join("src/lib.rs"),
        "pub const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();
    let report = inspect(target.path(), "integration").unwrap();
    let mut report: ReplayIsolationReport =
        serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(!report.passed());
    report.status = ReplayIsolationStatus::Passed;
    assert!(!report.passed());
    report.violations.clear();
    report.omitted_violations = 1;
    assert!(!report.passed());
    report.omitted_violations = 0;
    report.schema_version = 1;
    assert!(!report.passed());
}

#[test]
fn reports_replay_literals_on_added_lines_without_echoing_the_complete_value() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::write(
        target.path().join("src/lib.rs"),
        "pub const CACHE: &str = \"fake-node-10-2-29-229.trp.test:15138\";\n",
    )
    .unwrap();

    let report = inspect(target.path(), "integration").unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["status"], "failed");
    assert_eq!(value["violations"][0]["file"], "src/lib.rs");
    assert_eq!(value["violations"][0]["line"], 1);
    assert_eq!(value["violations"][0]["matched"], ".trp.test");
    assert!(!value.to_string().contains("fake-node-10-2-29-229"));
}

#[test]
fn checks_added_test_code_comments_and_invalid_rust_without_parsing_syntax() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::create_dir_all(target.path().join("tests")).unwrap();
    fs::write(
        target.path().join("src/lib.rs"),
        "this is not Rust // cache.trp.test\n",
    )
    .unwrap();
    fs::write(
        target.path().join("tests/integration.rs"),
        "const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();

    let report = inspect(target.path(), "integration").unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["scanned_files"], 2);
    assert_eq!(value["violations"].as_array().unwrap().len(), 2);
    assert!(
        value["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|violation| violation["file"] == "tests/integration.rs")
    );
}

#[test]
fn ignores_forbidden_literals_on_unchanged_lines_in_modified_files() {
    let target = target_with_source(
        "pub const LEGACY: &str = \"vintage-node-legacy.trp.test:15138\";\n\
         pub fn value() -> u8 { 1 }\n",
    );
    fs::write(
        target.path().join("src/lib.rs"),
        "pub const LEGACY: &str = \"vintage-node-legacy.trp.test:15138\";\n\
         pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();

    let report = inspect(target.path(), "integration").unwrap();

    assert!(report.passed());
    assert_eq!(report.scanned_files, 1);
    assert_eq!(report.scanned_added_lines, 1);
}

#[test]
fn ignores_forbidden_literals_in_an_unchanged_rename() {
    let target =
        target_with_source("pub const LEGACY: &str = \"vintage-node-legacy.trp.test:15138\";\n");
    git(target.path(), &["mv", "src/lib.rs", "src/renamed.rs"]);

    let report = inspect(target.path(), "integration").unwrap();

    assert!(report.passed());
    assert_eq!(report.scanned_added_lines, 0);
}

#[test]
fn scans_added_lines_in_nested_and_untracked_rust_sources() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::create_dir_all(target.path().join("crates/client/src")).unwrap();
    fs::create_dir_all(target.path().join("examples")).unwrap();
    fs::write(
        target.path().join("crates/client/src/lib.rs"),
        "const FAKE: &str = concat!(\"198.18.\", \"1.2\");\n",
    )
    .unwrap();
    fs::write(
        target.path().join("examples/demo.rs"),
        "const DATA: &[u8] = b\"dependencies.jsonl\";\n",
    )
    .unwrap();

    let report = inspect(target.path(), "integration").unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["scanned_files"], 2);
    assert_eq!(value["violations"].as_array().unwrap().len(), 1);
    assert_eq!(value["violations"][0]["rule"], "fake_ip_range");
}

#[test]
fn nested_target_scopes_diff_to_the_project_and_managed_siblings() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("services/backend");
    fs::create_dir_all(target.join("src")).unwrap();
    fs::create_dir_all(repository.path().join("sibling/src")).unwrap();
    traffic_engine::test_support::install_project_config(
        &target,
        "integration",
        traffic_engine::test_support::managed_test_recorder(),
        Some(serde_json::json!([])),
    );
    fs::write(target.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
    fs::write(
        repository.path().join("sibling/src/lib.rs"),
        "pub fn sibling() {}\n",
    )
    .unwrap();
    git(repository.path(), &["init", "-q", "-b", "integration"]);
    git(repository.path(), &["add", "."]);
    commit(repository.path(), "baseline");
    git(repository.path(), &["switch", "-q", "-c", "feature"]);

    fs::write(target.join("src/lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    fs::write(
        repository.path().join("sibling/src/lib.rs"),
        "pub const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();
    git(repository.path(), &["add", "."]);
    commit(repository.path(), "Update nested target and sibling");

    let report = inspect(&target, "integration").unwrap();

    assert!(report.passed());
    assert_eq!(report.scanned_files, 1);
    assert_eq!(report.scanned_added_lines, 1);

    traffic_engine::test_support::set_managed_paths(&target, &["../../sibling"]);
    let managed_report = inspect(&target, "integration").unwrap();

    assert!(!managed_report.passed());
    assert_eq!(managed_report.scanned_files, 2);
    assert_eq!(managed_report.scanned_added_lines, 2);
    assert!(
        managed_report
            .violations
            .iter()
            .any(|violation| violation.file == Path::new("../../sibling/src/lib.rs"))
    );
}

#[test]
fn compares_an_independent_worktree_with_the_shared_pr_base() {
    let root = tempfile::tempdir().unwrap();
    let primary = root.path().join("primary");
    let worker = root.path().join("worker");
    initialize_base(&primary, "pub fn value() -> u8 { 1 }\n");
    git(
        &primary,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feature",
            worker.to_str().unwrap(),
            "integration",
        ],
    );
    fs::write(
        worker.join("src/lib.rs"),
        "pub const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();

    let report = inspect(&worker, "integration").unwrap();

    assert!(!report.passed());
    assert_eq!(report.scanned_files, 1);
}

fn target_with_source(source: &str) -> tempfile::TempDir {
    let target = tempfile::tempdir().unwrap();
    initialize_base(target.path(), source);
    git(target.path(), &["switch", "-q", "-c", "feature"]);
    target
}

fn initialize_base(target: &Path, source: &str) {
    fs::create_dir_all(target.join("src")).unwrap();
    fs::write(target.join("src/lib.rs"), source).unwrap();
    git(target, &["init", "-q", "-b", "integration"]);
    git(target, &["add", "."]);
    commit(target, "baseline");
}

fn commit(target: &Path, subject: &str) {
    let mut command = Command::new("git");
    command.arg("-C").arg(target).args([
        "-c",
        "user.name=Traffic E2E Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-q",
        "-m",
        subject,
    ]);
    assert!(command.status().unwrap().success());
}

fn git(target: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(target)
            .args(args)
            .status()
            .unwrap()
            .success(),
        "git command failed: {args:?}"
    );
}
