use std::fs;
use std::path::Path;
use std::process::Command;

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
    use crate::rewrite::source_diff::git_text;
    let root = crate::rewrite::worker::tests::configured_target();
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
fn final_stage_is_distinct_even_without_cargo_and_tracks_manifest_changes() {
    let root = repository();
    let final_report = run_pre_revalidation(root.path(), "integration", &[], &[]).unwrap();
    assert!(final_report.passed_for(QualityScope::PreRevalidation));
    final_report
        .ensure_pre_revalidation(root.path(), &[])
        .unwrap();
    assert!(!final_report.passed());
    assert!(!final_report.passed_for(QualityScope::Worker));
    let ordinary = run(root.path(), "integration", &[]).unwrap();
    assert_ne!(ordinary.policy_fingerprint, final_report.policy_fingerprint);
    assert!(ordinary.ensure_pre_revalidation(root.path(), &[]).is_err());
    assert_eq!(final_gate_names(root.path(), &[]), gate_names());

    // A no-Cargo receipt cannot authorize a candidate that now has a manifest.
    fs::write(root.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    assert!(
        final_report
            .ensure_pre_revalidation(root.path(), &[])
            .is_err()
    );
}

fn successful_final_receipt(root: &Path, managed_paths: &[PathBuf]) -> QualityReport {
    // Derive a receipt without launching Cargo. Execution is covered separately
    // with controlled commands; admission must validate this complete inventory.
    let mut report = run_worker(root, "integration", &[]).unwrap();
    let gates = commands::inferred(root, managed_paths);
    report.scope = Some(QualityScope::PreRevalidation);
    report.policy_fingerprint =
        policy_fingerprint_for(QualityScope::PreRevalidation, &gates).unwrap();
    report.commands = gates
        .into_iter()
        .enumerate()
        .map(|(index, gate)| QualityCommandReport {
            name: gate.name,
            argv: gate.argv,
            working_directory: gate.working_directory,
            status: QualityCommandStatus::Passed,
            exit_code: Some(0),
            log_path: root.join(format!("quality-{index}.log")),
            error: None,
        })
        .collect();
    report
}

#[test]
fn final_receipt_requires_complete_canonical_commands_and_candidate_manifests() {
    let root = repository();
    fs::write(root.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    let good = successful_final_receipt(root.path(), &[]);
    good.ensure_pre_revalidation(root.path(), &[]).unwrap();
    assert!(good.passed_for(QualityScope::PreRevalidation));
    assert_eq!(
        final_gate_names(root.path(), &[]),
        [
            "source-review",
            "replay-isolation",
            "rust-format",
            "rust-test",
            "rust-clippy"
        ]
    );
    let mut deleted = good.clone();
    deleted.commands.pop();
    assert!(deleted.ensure_pre_revalidation(root.path(), &[]).is_err());
    // Even a coherently rewritten receipt must match the candidate-derived list.
    deleted.policy_fingerprint =
        policy_fingerprint_for(QualityScope::PreRevalidation, &deleted.command_specs()).unwrap();
    assert!(deleted.ensure_pre_revalidation(root.path(), &[]).is_err());
    let mut altered = good.clone();
    altered.commands[2].argv.pop();
    altered.policy_fingerprint =
        policy_fingerprint_for(QualityScope::PreRevalidation, &altered.command_specs()).unwrap();
    assert!(altered.ensure_pre_revalidation(root.path(), &[]).is_err());
    let mut wrong_directory = good.clone();
    wrong_directory.commands[0].working_directory = PathBuf::from("../other");
    wrong_directory.policy_fingerprint = policy_fingerprint_for(
        QualityScope::PreRevalidation,
        &wrong_directory.command_specs(),
    )
    .unwrap();
    assert!(
        wrong_directory
            .ensure_pre_revalidation(root.path(), &[])
            .is_err()
    );
    let mut reordered = good.clone();
    reordered.commands.swap(0, 1);
    assert!(reordered.ensure_pre_revalidation(root.path(), &[]).is_err());
    let mut disguised = good.clone();
    disguised.scope = Some(QualityScope::Worker);
    disguised.policy_fingerprint =
        policy_fingerprint_for(QualityScope::Worker, &disguised.command_specs()).unwrap();
    assert!(disguised.ensure_passed_for(QualityScope::Worker).is_err());
    assert!(disguised.ensure_pre_revalidation(root.path(), &[]).is_err());
    for index in 0..good.commands.len() {
        let mut failed = good.clone();
        failed.commands[index].status = QualityCommandStatus::Failed;
        assert!(failed.ensure_pre_revalidation(root.path(), &[]).is_err());
    }
    let mut no_exit = good.clone();
    no_exit.commands[0].exit_code = None;
    assert!(no_exit.ensure_pre_revalidation(root.path(), &[]).is_err());
    let mut error = good;
    error.commands[1].error = Some("spawn failed".into());
    assert!(error.ensure_pre_revalidation(root.path(), &[]).is_err());
}

#[test]
fn managed_rust_projects_get_project_scoped_final_checks() {
    let repository = tempfile::tempdir().unwrap();
    let target = repository.path().join("target-service");
    let sibling = repository.path().join("backend-rs");
    let docs = repository.path().join("docs");
    for directory in [&target, &sibling, &docs] {
        fs::create_dir(directory).unwrap();
    }
    fs::write(sibling.join("Cargo.toml"), "[workspace]\n").unwrap();
    let managed = [PathBuf::from("../docs"), PathBuf::from("../backend-rs")];
    let inferred = commands::inferred(&target, &managed);
    assert_eq!(inferred.len(), 3);
    assert_eq!(inferred[0].name, "managed-2-rust-format");
    assert_eq!(inferred[1].name, "managed-2-rust-test");
    assert_eq!(inferred[2].name, "managed-2-rust-clippy");
    assert!(
        inferred
            .iter()
            .all(|gate| gate.working_directory == Path::new("../backend-rs"))
    );
    assert_eq!(inferred[0].argv, ["cargo", "fmt", "--all", "--check"]);
    assert_eq!(inferred[1].argv, ["cargo", "test", "--workspace"]);
    assert_eq!(
        inferred[2].argv,
        [
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings"
        ]
    );
    fs::write(target.join("Cargo.toml"), "[workspace]\n").unwrap();
    let with_root = commands::inferred(&target, &managed);
    assert_eq!(with_root.len(), 6);
    assert!(
        with_root[..3]
            .iter()
            .all(|gate| gate.working_directory == Path::new("."))
    );
}

#[test]
fn final_command_execution_is_serial_retains_logs_and_stops_after_failure() {
    let root = repository();
    let gates = [
        ("first", "printf 'first stdout'; printf 'first stderr' >&2"),
        ("second", "printf 'second stderr' >&2; exit 17"),
        ("third", "touch must-not-run"),
    ]
    .into_iter()
    .map(|(name, script)| commands::CommandSpec {
        name: name.to_string(),
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
        working_directory: PathBuf::from("."),
    })
    .collect::<Vec<_>>();
    let reports = commands::run(root.path(), &gates).unwrap();
    assert_eq!(reports.len(), 2);
    assert!(reports[0].passed());
    assert!(!reports[1].passed());
    assert_eq!(reports[1].exit_code, Some(17));
    assert!(!root.path().join("must-not-run").exists());
    let first_log = fs::read_to_string(&reports[0].log_path).unwrap();
    assert!(first_log.contains("first stdout"));
    assert!(first_log.contains("first stderr"));
    let second_log = fs::read_to_string(&reports[1].log_path).unwrap();
    assert!(second_log.contains("second stderr"));
    assert!(second_log.contains("quality gate execution failed:"));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&reports[0].log_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn final_command_spawn_failure_is_a_failed_receipt_with_a_log() {
    let root = repository();
    let report = commands::run(
        root.path(),
        &[commands::CommandSpec {
            name: "missing-tool".into(),
            working_directory: PathBuf::from("."),
            argv: vec![
                root.path()
                    .join("not-installed")
                    .to_string_lossy()
                    .into_owned(),
            ],
        }],
    )
    .unwrap()
    .pop()
    .unwrap();
    assert!(!report.passed());
    assert_eq!(report.exit_code, None);
    assert!(report.error.is_some());
    assert!(
        fs::read_to_string(report.log_path)
            .unwrap()
            .contains("failed to execute quality gate")
    );
}

#[test]
fn final_review_does_not_execute_cargo_after_isolation_fails() {
    let root = repository();
    fs::write(root.path().join("Cargo.toml"), "invalid Cargo manifest\n").unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "pub const DOMAIN: &str = \"demo.test\";\n",
    )
    .unwrap();
    let report = run_pre_revalidation(root.path(), "integration", &[], &[]).unwrap();
    assert!(report.commands.is_empty());
    assert!(
        !crate::internal_runtime::root(root.path())
            .join("rewrite/quality")
            .exists()
    );
    assert!(
        report
            .ensure_pre_revalidation(root.path(), &[])
            .unwrap_err()
            .to_string()
            .contains("target replay isolation gate failed:")
    );
}

#[test]
fn managed_commands_execute_from_their_project_and_remain_portable() {
    let root = repository();
    let managed = root.path().join("managed");
    fs::create_dir(&managed).unwrap();
    fs::write(managed.join("project-marker"), "managed cwd").unwrap();
    let report = commands::run(
        root.path(),
        &[commands::CommandSpec {
            name: "managed-working-directory".into(),
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "pwd; cat project-marker".into(),
            ],
            working_directory: PathBuf::from("managed"),
        }],
    )
    .unwrap()
    .pop()
    .unwrap();
    assert!(report.passed());
    assert_eq!(report.working_directory, Path::new("managed"));
    let log = fs::read_to_string(&report.log_path).unwrap();
    assert!(log.lines().any(|line| Path::new(line) == managed));
    assert!(log.contains("managed cwd"));

    let replica = tempfile::tempdir().unwrap();
    fs::create_dir(replica.path().join("managed")).unwrap();
    fs::write(managed.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(replica.path().join("managed/Cargo.toml"), "[workspace]\n").unwrap();
    assert_eq!(
        commands::inferred(root.path(), &[PathBuf::from("managed")]),
        commands::inferred(replica.path(), &[PathBuf::from("managed")])
    );
}
