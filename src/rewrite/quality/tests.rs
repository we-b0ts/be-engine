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

fn gate(name: &str, argv: &[&str]) -> TargetQualityGateConfig {
    TargetQualityGateConfig {
        name: name.into(),
        argv: argv.iter().map(|argument| (*argument).into()).collect(),
    }
}

#[test]
fn runs_in_delivery_worktree_and_retains_stdout_and_stderr_outside_product_code() {
    let root = repository();
    let gates = vec![gate(
        "check",
        &[
            "sh",
            "-c",
            "test -f src/lib.rs && printf 'stdout evidence\\n' && printf 'stderr evidence\\n' >&2",
        ],
    )];
    let before = fingerprint::repository_fingerprint(root.path()).unwrap();

    let report = run(root.path(), "integration", &gates, &[]).unwrap();

    assert!(report.passed(&gates));
    report.ensure_passed(&gates).unwrap();
    let command = &report.commands[0];
    let log = fs::read_to_string(&command.log_path).unwrap();
    assert!(log.contains("stdout evidence"));
    assert!(log.contains("stderr evidence"));
    assert!(
        command
            .log_path
            .starts_with(crate::internal_runtime::root(root.path()))
    );
    assert!(git(root.path(), &["status", "--porcelain"]).is_empty());
    assert_eq!(
        before,
        fingerprint::repository_fingerprint(root.path()).unwrap()
    );
    let round_trip: QualityReport =
        serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(round_trip.passed(&gates));
}

#[test]
fn persists_nonzero_gate_failure_and_does_not_execute_later_gates() {
    let root = repository();
    let gates = vec![
        gate(
            "rust-clippy",
            &[
                "sh",
                "-c",
                "printf 'private_interfaces warning\\n' >&2; exit 101",
            ],
        ),
        gate("later", &["sh", "-c", "touch should-not-run"]),
    ];

    let report = run(root.path(), "integration", &gates, &[]).unwrap();

    assert!(!report.passed(&gates));
    assert_eq!(report.commands.len(), 1);
    assert_eq!(report.commands[0].exit_code, Some(101));
    assert_eq!(report.commands[0].status, QualityCommandStatus::Failed);
    assert!(!root.path().join("should-not-run").exists());
    let failure = report.ensure_passed(&gates).unwrap_err().to_string();
    assert!(failure.contains("rust-clippy"));
    assert!(failure.contains("101"));
    assert!(failure.contains(report.commands[0].log_path.to_str().unwrap()));
    assert!(
        fs::read_to_string(&report.commands[0].log_path)
            .unwrap()
            .contains("private_interfaces warning")
    );
    let round_trip: QualityReport =
        serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(!round_trip.passed(&gates));
}

#[test]
fn retains_startup_failure_in_report_instead_of_losing_the_gate_identity() {
    let root = repository();
    let gates = vec![gate(
        "missing-tool",
        &["/missing-quality-executable-for-test"],
    )];

    let report = run(root.path(), "integration", &gates, &[]).unwrap();

    assert!(!report.passed(&gates));
    let command = &report.commands[0];
    assert_eq!(command.exit_code, None);
    assert_eq!(command.status, QualityCommandStatus::Failed);
    assert!(command.error.as_ref().unwrap().contains("missing-tool"));
    assert!(
        fs::read_to_string(&command.log_path)
            .unwrap()
            .contains("missing-tool")
    );
}

#[test]
fn rejects_stale_policies_incomplete_commands_and_changed_arguments() {
    let root = repository();
    let gates = vec![
        gate("first", &["sh", "-c", "true"]),
        gate("second", &["sh", "-c", "true"]),
    ];
    let report = run(root.path(), "integration", &gates, &[]).unwrap();
    assert!(report.passed(&gates));

    let mut altered = gates.clone();
    altered[0].argv[2] = "false".into();
    assert_ne!(
        policy_fingerprint(&gates).unwrap(),
        policy_fingerprint(&altered).unwrap()
    );
    assert!(!report.passed(&altered));
    altered = gates.clone();
    altered[0].name = "renamed".into();
    assert!(!report.passed(&altered));
    altered = gates.clone();
    altered.swap(0, 1);
    assert!(!report.passed(&altered));

    let mut incomplete = report.clone();
    incomplete.commands.pop();
    assert!(!incomplete.passed(&gates));
    assert!(
        incomplete
            .ensure_passed(&gates)
            .unwrap_err()
            .to_string()
            .contains("1 of 2")
    );
    let mut wrong_arguments = report.clone();
    wrong_arguments.commands[0].argv[2] = "false".into();
    assert!(!wrong_arguments.passed(&gates));
    let mut wrong_order = report.clone();
    wrong_order.commands.swap(0, 1);
    assert!(!wrong_order.passed(&gates));
    let mut wrong_exit = report;
    wrong_exit.commands[0].exit_code = Some(101);
    assert!(!wrong_exit.passed(&gates));
}

#[test]
fn source_sensitive_domains_in_tests_block_delivery_before_configured_commands() {
    let root = repository();
    fs::create_dir(root.path().join("tests")).unwrap();
    fs::write(
        root.path().join("tests/auth.rs"),
        "const EMAIL: &str = \"fixture@demo.test\";\nconst API: &str = \"sample.test\";\n",
    )
    .unwrap();
    let gates = vec![gate("later", &["sh", "-c", "touch should-not-run"])];

    let report = run(root.path(), "integration", &gates, &[]).unwrap();

    assert!(!report.passed(&gates));
    assert!(report.commands.is_empty());
    assert!(!root.path().join("should-not-run").exists());
    let error = report.ensure_passed(&gates).unwrap_err().to_string();
    assert!(error.starts_with("target replay isolation gate failed:"));
    assert!(error.contains("tests/auth.rs"));
    assert!(error.contains("demo.test"));
    assert!(error.contains("sample.test"));
    assert!(error.contains("Hardcode-Source-Evidence"));
}

#[test]
fn builtin_gates_are_required_even_without_configured_commands() {
    let root = repository();
    assert_eq!(gate_names(&[]), ["source-review", "replay-isolation"]);
    let report = run(root.path(), "integration", &[], &[]).unwrap();
    assert!(report.passed(&[]));
    fs::write(
        root.path().join("src/lib.rs"),
        "pub const CACHE: &str = \"cache.trp.test\";\n",
    )
    .unwrap();
    let report = run(root.path(), "integration", &[], &[]).unwrap();
    assert!(!report.passed(&[]));
}

#[test]
fn frozen_commit_base_scans_inherited_violations_after_the_branch_moves() {
    use crate::rewrite::source_diff::git_text;

    let root = crate::rewrite::worker::tests::configured_target();
    let base = git_text(root.path(), &["rev-parse", "HEAD"])
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(base.len(), 40);
    assert!(run(root.path(), &base, &[], &[]).unwrap().passed(&[]));
    std::fs::write(
        root.path().join("lib.rs"),
        "pub const DOMAIN: &str = \"demo.test\";\n",
    )
    .unwrap();
    git_text(root.path(), &["add", "lib.rs"]).unwrap();
    git_text(root.path(), &["commit", "-qm", "inherited domain"]).unwrap();

    let report = run(root.path(), &base, &[], &[]).unwrap();

    assert!(!report.passed(&[]));
    assert!(
        report
            .ensure_passed(&[])
            .unwrap_err()
            .to_string()
            .contains("demo.test")
    );
}
