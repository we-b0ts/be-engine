//! Worker receipts cannot stand in for complete integration checks.
use super::*;
use crate::rewrite::quality::QualityScope;

#[test]
fn worker_handoff_skips_cargo_but_requires_its_current_source_isolation_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let invoked = directory.path().join("cargo-invoked");
    let target = target();
    enable_standard_rust_checks(
        target.path(),
        &format!(
            "fn main() {{\n    std::fs::write({path:?}, \"called\").unwrap();\n    panic!(\"worker review must not build\");\n}}\n",
            path = invoked.to_string_lossy(),
        ),
    );
    let worker = worktree(target.path(), directory.path(), "worker");
    let scope = worker_scope(target.path(), &worker);
    // Neither formatting nor compiler/test failures belong to worker review.
    fs::write(
        worker.join("lib.rs"),
        "pub fn value() -> u8 {\n    \"not a number\"\n}\n",
    )
    .unwrap();
    git(&worker, &["add", "lib.rs"]);
    git(&worker, &["commit", "-qm", "worker implementation"]);
    let report = check(options(target.path(), &worker, Some(scope.clone()))).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert_eq!(report.required_gates, ["source-review", "replay-isolation"]);
    let quality = report.quality.as_ref().unwrap();
    assert_eq!(quality.scope, Some(QualityScope::Worker));
    assert!(quality.commands.is_empty());
    assert!(!invoked.exists());

    let handoff = delivery(target.path(), &scope, &report);
    for variant in ["missing_quality", "missing_scope", "old_schema"] {
        let mut incomplete = report.clone();
        match variant {
            "missing_quality" => incomplete.quality = None,
            "missing_scope" => incomplete.quality.as_mut().unwrap().scope = None,
            "old_schema" => incomplete.quality.as_mut().unwrap().schema_version = 1,
            _ => unreachable!(),
        }
        write_json(&report.report_path, &incomplete).unwrap();
        let error = worker::runtime::report(handoff.clone()).unwrap_err();
        assert!(
            error.to_string().contains("quality"),
            "{variant}: {error:#}"
        );
    }
    let store = RewriteStore::new(target.path()).unwrap();
    assert!(worker::runtime::observation(&store.load().unwrap().unwrap(), &scope).is_none());
    write_json(&report.report_path, &report).unwrap();
    worker::runtime::report(handoff).unwrap();
    assert_eq!(
        worker::runtime::observation(&store.load().unwrap().unwrap(), &scope)
            .unwrap()
            .activity,
        RewriteWorkerActivity::HandoffReady
    );
    assert!(!invoked.exists());
}

#[test]
fn worker_quality_cannot_be_relabelled_as_integration_even_without_cargo_gates() {
    for with_cargo in [false, true] {
        let target = target();
        if with_cargo {
            enable_standard_rust_checks(target.path(), "fn main() {}\n");
        }
        let directory = tempfile::tempdir().unwrap();
        let worker = worktree(target.path(), directory.path(), "worker");
        let scope = worker_scope(target.path(), &worker);
        let worker_report = check(options(target.path(), &worker, Some(scope))).unwrap();
        let integration_report = check(options(target.path(), &worker, None)).unwrap();
        assert_eq!(worker_report.status, ReviewStatus::Passed);
        assert_eq!(integration_report.status, ReviewStatus::Passed);
        if !with_cargo {
            assert!(
                integration_report
                    .quality
                    .as_ref()
                    .unwrap()
                    .commands
                    .is_empty()
            );
        }
        assert_ne!(
            worker_report.quality.as_ref().unwrap().policy_fingerprint,
            integration_report
                .quality
                .as_ref()
                .unwrap()
                .policy_fingerprint
        );
        for scope in [
            Some(QualityScope::Worker),
            Some(QualityScope::Integration),
            None,
        ] {
            let mut forged = integration_report.clone();
            forged.quality = worker_report.quality.clone();
            forged.quality.as_mut().unwrap().scope = scope;
            // Display metadata cannot remove the configured integration gates.
            forged.required_gates = worker_report.required_gates.clone();
            write_json(&integration_report.report_path, &forged).unwrap();
            let error =
                accept(target.path().into(), integration_report.report_path.clone()).unwrap_err();
            assert!(
                error.to_string().contains("quality"),
                "{scope:?}: {error:#}"
            );
        }
        write_json(&integration_report.report_path, &integration_report).unwrap();
        accept(target.path().into(), integration_report.report_path).unwrap();
        let state = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(terminal_current(target.path(), &state));
    }
}

#[test]
fn persisted_accepted_receipt_requires_integration_identity_and_quality_scope() {
    let target = target();
    let directory = tempfile::tempdir().unwrap();
    let worker = worktree(target.path(), directory.path(), "worker");
    let scope = worker_scope(target.path(), &worker);
    let worker_report = check(options(target.path(), &worker, Some(scope))).unwrap();
    let integration_report = check(options(target.path(), &worker, None)).unwrap();
    accept(target.path().into(), integration_report.report_path).unwrap();
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    let path = integrated_path(target.path());
    let accepted: RewriteReviewReport = read_json(&path).unwrap();
    assert!(terminal_current(target.path(), &state));
    for variant in [
        "missing_integration",
        "worker_quality",
        "missing_scope",
        "old_schema",
    ] {
        let mut invalid = accepted.clone();
        match variant {
            "missing_integration" => {
                invalid.integration = None;
                invalid.quality = worker_report.quality.clone();
            }
            "worker_quality" => invalid.quality = worker_report.quality.clone(),
            "missing_scope" => invalid.quality.as_mut().unwrap().scope = None,
            "old_schema" => invalid.quality.as_mut().unwrap().schema_version = 1,
            _ => unreachable!(),
        }
        write_json(&path, &invalid).unwrap();
        assert!(!terminal_current(target.path(), &state), "{variant}");
        assert!(
            integrated::current(target.path(), &state)
                .unwrap()
                .is_none()
        );
    }
    write_json(&path, &accepted).unwrap();
    assert!(terminal_current(target.path(), &state));
}
