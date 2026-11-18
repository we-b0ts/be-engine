use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use traffic_rewrite_model::rewrite::quality::{QualityCommandReport, QualityCommandStatus};

use super::*;

fn repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["config", "user.name", "Quality Test"]);
    git(
        root.path(),
        &["config", "user.email", "quality@example.test"],
    );
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
    fs::write(root.path().join(".gitignore"), ".traffic-e2e/local/\n").unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "base"]);
    git(root.path(), &["branch", "integration"]);
    root
}

fn git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn review_receipts_are_stage_bound_and_never_execute_repository_commands() {
    let root = repository();
    // An unusable manifest would fail any Cargo command. Ordinary reviews must
    // perform no repository commands even when Rust is detected.
    fs::write(root.path().join("Cargo.toml"), "invalid Cargo manifest\n").unwrap();
    let worker = run_worker(root.path(), "integration", &[]).unwrap();
    let integration = run(root.path(), "integration", &[]).unwrap();
    assert!(worker.passed_for(QualityScope::Worker));
    worker.ensure_passed_for(QualityScope::Worker).unwrap();
    assert!(integration.passed());
    integration.ensure_passed().unwrap();
    assert!(worker.commands.is_empty());
    assert!(integration.commands.is_empty());
    assert!(
        !crate::internal_runtime::root(root.path())
            .join("rewrite/quality")
            .exists()
    );
    assert_eq!(gate_names(), ["source-review", "replay-isolation"]);
    assert_ne!(worker.policy_fingerprint, integration.policy_fingerprint);
    assert!(!worker.passed());
    assert!(!integration.passed_for(QualityScope::Worker));
    let mut forged = worker.clone();
    forged.scope = Some(QualityScope::Integration);
    assert!(forged.ensure_passed().is_err());
    forged = worker;
    forged.policy_fingerprint = integration.policy_fingerprint.clone();
    assert!(forged.ensure_passed().is_err());
    let mut historical = serde_json::to_value(&integration).unwrap();
    historical.as_object_mut().unwrap().remove("scope");
    let historical: QualityReport = serde_json::from_value(historical).unwrap();
    assert!(historical.ensure_passed().is_err());
    let mut old_schema = integration;
    old_schema.schema_version = 1;
    assert!(old_schema.ensure_passed().is_err());
}

#[test]
fn source_sensitive_domains_in_tests_still_block_both_review_stages() {
    let root = repository();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(
        root.path().join("tests/auth.rs"),
        "const EMAIL: &str = \"fixture@demo.test\";\nconst API: &str = \"sample.test\";\n",
    )
    .unwrap();
    for report in [
        run_worker(root.path(), "integration", &[]).unwrap(),
        run(root.path(), "integration", &[]).unwrap(),
    ] {
        let scope = report.scope.unwrap();
        assert!(!report.passed_for(scope));
        let error = report.ensure_passed_for(scope).unwrap_err().to_string();
        assert!(error.starts_with("target replay isolation gate failed:"));
        assert!(error.contains("tests/auth.rs"));
        assert!(error.contains("demo.test"));
        assert!(error.contains("sample.test"));
        assert!(error.contains("Hardcode-Source-Evidence"));
    }
}

#[test]
fn frozen_commit_base_scans_inherited_violations_after_the_branch_moves() {
    use crate::source_diff::git_text;
    let root = crate::worker::tests::configured_target();
    let base = git_text(root.path(), &["rev-parse", "HEAD"])
        .unwrap()
        .trim()
        .to_string();
    assert!(run(root.path(), &base, &[]).unwrap().passed());
    fs::write(
        root.path().join("lib.rs"),
        "pub const DOMAIN: &str = \"demo.test\";\n",
    )
    .unwrap();
    git_text(root.path(), &["add", "lib.rs"]).unwrap();
    git_text(root.path(), &["commit", "-qm", "inherited domain"]).unwrap();
    let report = run(root.path(), &base, &[]).unwrap();
    assert!(!report.passed());
    assert!(
        report
            .ensure_passed()
            .unwrap_err()
            .to_string()
            .contains("demo.test")
    );
}

#[test]
fn final_quality_is_agent_reported_and_never_executes_repository_commands() {
    let root = repository();
    // Even final review must not invoke Cargo against this unusable manifest.
    fs::write(root.path().join("Cargo.toml"), "invalid Cargo manifest\n").unwrap();
    for tool in [
        "cargo-clippy",
        "eslint",
        "ruff",
        "golangci-lint",
        "project-quality",
    ] {
        let report = run_pre_revalidation(root.path(), "integration", tool, &[]).unwrap();
        report.ensure_pre_revalidation(tool).unwrap();
        assert_eq!(report.quality_check.as_deref(), Some(tool));
        assert!(report.commands.is_empty());
        assert!(!report.passed());
        assert!(!report.passed_for(QualityScope::Worker));
        assert!(
            !crate::internal_runtime::root(root.path())
                .join("rewrite/quality")
                .exists()
        );
    }
    assert_eq!(
        final_gate_names(),
        ["source-review", "replay-isolation", "agent-quality-check"]
    );
}

#[test]
fn final_quality_requires_the_current_tool_and_cannot_be_relabelled() {
    let root = repository();
    let good = run_pre_revalidation(root.path(), "integration", "cargo-clippy", &[]).unwrap();
    good.ensure_pre_revalidation("cargo-clippy").unwrap();
    assert!(good.ensure_pre_revalidation("eslint").is_err());
    let ordinary = run(root.path(), "integration", &[]).unwrap();
    assert!(ordinary.ensure_pre_revalidation("cargo-clippy").is_err());
    for tool in [None, Some("".to_string()), Some("eslint".to_string())] {
        let mut invalid = good.clone();
        invalid.quality_check = tool;
        assert!(invalid.ensure_pre_revalidation("cargo-clippy").is_err());
    }
    let mut relabelled = good.clone();
    relabelled.scope = Some(QualityScope::Integration);
    assert!(relabelled.ensure_passed().is_err());
    let mut relabelled = ordinary;
    relabelled.scope = Some(QualityScope::PreRevalidation);
    relabelled.quality_check = Some("cargo-clippy".into());
    assert!(relabelled.ensure_pre_revalidation("cargo-clippy").is_err());
    let other = run_pre_revalidation(root.path(), "integration", "eslint", &[]).unwrap();
    assert_ne!(good.policy_fingerprint, other.policy_fingerprint);
    let mut old_schema = good;
    old_schema.schema_version = 2;
    assert!(old_schema.ensure_pre_revalidation("cargo-clippy").is_err());
}

#[test]
fn historical_command_results_do_not_authorize_current_final_quality() {
    let root = repository();
    let mut report = run_pre_revalidation(root.path(), "integration", "cargo-clippy", &[]).unwrap();
    report.commands.push(QualityCommandReport {
        name: "rust-clippy".into(),
        argv: vec!["cargo".into(), "clippy".into()],
        working_directory: PathBuf::from("."),
        status: QualityCommandStatus::Passed,
        exit_code: Some(0),
        log_path: root.path().join("historical.log"),
        error: None,
    });
    assert!(report.ensure_pre_revalidation("cargo-clippy").is_err());
}

#[test]
fn final_agent_quality_report_does_not_bypass_isolation() {
    let root = repository();
    fs::write(
        root.path().join("src/lib.rs"),
        "pub const DOMAIN: &str = \"demo.test\";\n",
    )
    .unwrap();
    let report = run_pre_revalidation(root.path(), "integration", "cargo-clippy", &[]).unwrap();
    assert!(
        report
            .ensure_pre_revalidation("cargo-clippy")
            .unwrap_err()
            .to_string()
            .contains("target replay isolation gate failed:")
    );
}
