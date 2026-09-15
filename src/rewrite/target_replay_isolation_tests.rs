use super::*;
use std::fs;

#[test]
fn persisted_report_cannot_pass_with_remaining_violations_or_an_obsolete_schema() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::write(
        target.path().join("src/lib.rs"),
        "pub const DOMAIN: &str = \"demo.test\";\n",
    )
    .unwrap();
    let report = inspect(target.path(), "integration", &[]).unwrap();
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

    let report = inspect(target.path(), "integration", &[]).unwrap();
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

    let report = inspect(target.path(), "integration", &[]).unwrap();
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

    let report = inspect(target.path(), "integration", &[]).unwrap();

    assert!(report.passed());
    assert_eq!(report.scanned_files, 1);
    assert_eq!(report.scanned_added_lines, 1);
}

#[test]
fn ignores_forbidden_literals_in_an_unchanged_rename() {
    let target =
        target_with_source("pub const LEGACY: &str = \"vintage-node-legacy.trp.test:15138\";\n");
    git(target.path(), &["mv", "src/lib.rs", "src/renamed.rs"]);

    let report = inspect(target.path(), "integration", &[]).unwrap();

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

    let report = inspect(target.path(), "integration", &[]).unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["scanned_files"], 2);
    assert_eq!(value["violations"].as_array().unwrap().len(), 1);
    assert_eq!(value["violations"][0]["rule"], "fake_ip_range");
}

#[test]
fn source_sensitive_domains_require_an_exact_ai_verification_position() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    let source = "pub const API: &str = \"https://API.demo.test/v1\";\n";
    fs::write(target.path().join("src/lib.rs"), source).unwrap();

    let report = inspect(target.path(), "integration", &[]).unwrap();
    let value = serde_json::to_value(report).unwrap();
    let violation = &value["violations"][0];

    assert_eq!(violation["rule"], "source_hardcoded_domain");
    assert_eq!(violation["matched"], "demo.test");
    assert_eq!(violation["line"], 1);
    assert_eq!(
        violation["column"].as_u64().unwrap() as usize,
        source.to_ascii_lowercase().find("demo.test").unwrap() + 1
    );
}

#[test]
fn source_sensitive_domains_are_checked_in_test_code_too() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::create_dir_all(target.path().join("tests")).unwrap();
    fs::write(
        target.path().join("tests/integration.rs"),
        "const API: &str = \"https://api.demo.test/v1\";\n",
    )
    .unwrap();

    let report = inspect(target.path(), "integration", &[]).unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["violations"][0]["file"], "tests/integration.rs");
    assert_eq!(value["violations"][0]["rule"], "source_hardcoded_domain");
}

#[test]
fn source_sensitive_domains_require_one_approval_per_occurrence() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::write(
        target.path().join("src/lib.rs"),
        "const PAIR: (&str, &str) = (\"demo.test\", \"demo.test\");\n",
    )
    .unwrap();

    let report = inspect(target.path(), "integration", &[]).unwrap();
    let value = serde_json::to_value(report).unwrap();

    assert_eq!(value["violations"].as_array().unwrap().len(), 2);
    assert_ne!(
        value["violations"][0]["column"],
        value["violations"][1]["column"]
    );
}

#[test]
fn rejects_stale_or_unmatched_hardcode_approvals() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    fs::write(
        target.path().join("src/lib.rs"),
        "pub const API: &str = \"https://api.demo.test/v1\";\n",
    )
    .unwrap();

    let error = inspect(
        target.path(),
        "integration",
        &["src/lib.rs:99:1=legacy-service@abcdef1:src/Client.java:96:27".to_string()],
    )
    .unwrap_err();

    assert!(error.to_string().contains("does not match a newly added"));
}

#[test]
fn approved_hardcode_must_be_committed() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    let source = "pub const API: &str = \"https://api.demo.test/v1\";\n";
    fs::write(target.path().join("src/lib.rs"), source).unwrap();
    let column = source.find("demo.test").unwrap() + 1;
    let approval = format!("src/lib.rs:1:{column}=legacy-service@abcdef1:src/Client.java:96:27");

    let error = inspect(
        target.path(),
        "integration",
        std::slice::from_ref(&approval),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("must refer to a committed occurrence")
    );
}

#[test]
fn approved_hardcode_requires_source_evidence_in_a_commit_trailer() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    let source = "pub const API: &str = \"https://api.demo.test/v1\";\n";
    fs::write(target.path().join("src/lib.rs"), source).unwrap();
    let column = source.find("demo.test").unwrap() + 1;
    let target_location = format!("src/lib.rs:1:{column}");
    let source_evidence = "legacy-service@abcdef1:src/Client.java:96:27";
    let approval = format!("{target_location}={source_evidence}");
    git(target.path(), &["add", "src/lib.rs"]);
    commit(target.path(), "Add endpoint without evidence", "");

    let error = inspect(target.path(), "integration", &[approval]).unwrap_err();

    assert!(error.to_string().contains("requires commit trailer"));
}

#[test]
fn accepts_exact_hardcode_approval_with_source_commit_evidence() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    let source = "pub const API: &str = \"https://api.sample.test/v1\";\n";
    fs::write(target.path().join("src/lib.rs"), source).unwrap();
    let column = source.find("sample.test").unwrap() + 1;
    let target_location = format!("src/lib.rs:1:{column}");
    let source_evidence = "legacy-service@abcdef1:src/Client.java:96:27";
    let approval = format!("{target_location}={source_evidence}");
    git(target.path(), &["add", "src/lib.rs"]);
    commit(
        target.path(),
        "Add source-compatible endpoint",
        &format!("Hardcode-Source-Evidence: {target_location} <= {source_evidence}"),
    );

    let report = inspect(target.path(), "integration", &[approval]).unwrap();

    assert!(report.passed());
}

#[test]
fn nested_target_scopes_diff_and_committed_evidence_to_the_project() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("services/backend");
    fs::create_dir_all(target.join("src")).unwrap();
    fs::create_dir_all(repository.path().join("sibling/src")).unwrap();
    crate::rewrite::test_support::install_project_config(
        &target,
        "integration",
        crate::rewrite::test_support::managed_test_recorder(),
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
    commit(repository.path(), "baseline", "");
    git(repository.path(), &["switch", "-q", "-c", "feature"]);

    let source = "pub const API: &str = \"https://api.sample.test/v1\";\n";
    fs::write(target.join("src/lib.rs"), source).unwrap();
    fs::write(
        repository.path().join("sibling/src/lib.rs"),
        "pub const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();
    let column = source.find("sample.test").unwrap() + 1;
    let target_location = format!("src/lib.rs:1:{column}");
    let source_evidence = "legacy-service@abcdef1:src/Client.java:96:27";
    let approval = format!("{target_location}={source_evidence}");
    git(repository.path(), &["add", "."]);
    commit(
        repository.path(),
        "Add nested source-compatible endpoint",
        &format!("Hardcode-Source-Evidence: {target_location} <= {source_evidence}"),
    );

    let report = inspect(&target, "integration", std::slice::from_ref(&approval)).unwrap();

    assert!(report.passed());
    assert_eq!(report.scanned_files, 1);
    assert_eq!(report.scanned_added_lines, 1);

    crate::rewrite::test_support::set_managed_paths(&target, &["../../sibling"]);
    let sibling_source = "pub const CACHE: &str = \"https://cache.sample.test/v1\";\n";
    fs::write(repository.path().join("sibling/src/lib.rs"), sibling_source).unwrap();
    let sibling_column = sibling_source.find("sample.test").unwrap() + 1;
    let sibling_location = format!("../../sibling/src/lib.rs:1:{sibling_column}");
    let sibling_approval = format!("{sibling_location}={source_evidence}");
    git(repository.path(), &["add", "."]);
    commit(
        repository.path(),
        "Manage sibling source-compatible endpoint",
        &format!("Hardcode-Source-Evidence: {sibling_location} <= {source_evidence}"),
    );
    let managed_pass = inspect(
        &target,
        "integration",
        &[approval.clone(), sibling_approval],
    )
    .unwrap();

    assert!(managed_pass.passed());
    assert_eq!(managed_pass.scanned_files, 2);

    fs::write(
        repository.path().join("sibling/src/lib.rs"),
        "pub const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();
    let managed_report = inspect(&target, "integration", std::slice::from_ref(&approval)).unwrap();

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
fn rejects_legacy_target_only_hardcode_approval_format() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");

    let error = inspect(
        target.path(),
        "integration",
        &["src/lib.rs:1:1".to_string()],
    )
    .unwrap_err();

    assert!(error.to_string().contains(
        "expected TARGET_FILE:LINE:COLUMN=SOURCE_REPOSITORY@REVISION:SOURCE_FILE:LINE:COLUMN"
    ));
}

#[test]
fn rejects_configuration_file_as_source_code_evidence() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    let source = "pub const API: &str = \"https://api.sample.test/v1\";\n";
    fs::write(target.path().join("src/lib.rs"), source).unwrap();
    let column = source.find("sample.test").unwrap() + 1;
    let approval = format!(
        "src/lib.rs:1:{column}=legacy-service@abcdef1:src/main/resources/application.properties:9:31"
    );

    let error = inspect(target.path(), "integration", &[approval]).unwrap_err();

    assert!(
        format!("{error:#}")
            .contains("configuration, resource, test, and example files cannot justify")
    );
}

#[test]
fn rejects_ai_verification_that_differs_from_committed_source_evidence() {
    let target = target_with_source("pub fn value() -> u8 { 1 }\n");
    let source = "pub const API: &str = \"https://api.sample.test/v1\";\n";
    fs::write(target.path().join("src/lib.rs"), source).unwrap();
    let column = source.find("sample.test").unwrap() + 1;
    let target_location = format!("src/lib.rs:1:{column}");
    git(target.path(), &["add", "src/lib.rs"]);
    commit(
        target.path(),
        "Add endpoint with different evidence",
        &format!(
            "Hardcode-Source-Evidence: {target_location} <= legacy-service@abcdef1:src/Client.java:96:27"
        ),
    );
    let approval = format!("{target_location}=legacy-service@abcdef1:src/OtherClient.java:41:18");

    let error = inspect(target.path(), "integration", &[approval]).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("does not match committed trailer")
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

    let report = inspect(&worker, "integration", &[]).unwrap();

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
    commit(target, "baseline", "");
}

fn commit(target: &Path, subject: &str, body: &str) {
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
    if !body.is_empty() {
        command.args(["-m", body]);
    }
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
