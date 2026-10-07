use super::*;
use crate::rewrite::worker::tests::{configured_target, implementation_state_with_inventory};

fn git(root: &Path, arguments: &[&str]) {
    source_diff::git_text(root, arguments).unwrap();
}

fn failed_candidate() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    RewriteWorkScope,
    RewriteReviewReport,
) {
    let target = configured_target();
    fs::write(target.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    git(target.path(), &["add", ".gitignore"]);
    git(target.path(), &["commit", "-qm", "ignore engine runtime"]);
    git(target.path(), &["switch", "-qc", "coordinator"]);
    let state = implementation_state_with_inventory(false);
    let scope = RewriteWorkScope::Api {
        api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
    };
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    worker::confirm(crate::rewrite::RewriteWorkerConfirmOptions {
        target_root: target.path().into(),
        work_scope: scope.clone(),
        worktree: Some(target.path().into()),
        agent_handle: "repair-worker".into(),
        agent_name: None,
    })
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let worktree = directory.path().join("candidate");
    git(
        target.path(),
        &[
            "worktree",
            "add",
            "-qb",
            "candidate",
            worktree.to_str().unwrap(),
        ],
    );
    fs::create_dir(worktree.join("src")).unwrap();
    fs::write(
        worktree.join("src/oversized.rs"),
        "// oversized source\n".repeat(1001),
    )
    .unwrap();
    git(&worktree, &["add", "src/oversized.rs"]);
    git(
        &worktree,
        &["commit", "-qm", "candidate requiring source repair"],
    );
    let report = check(RewriteReviewOptions {
        target_root: target.path().into(),
        worktree: Some(worktree),
        integration: true,
        scope: None,
        handoff_id: None,
        evidence: None,
        hardcode_ai_verified: Vec::new(),
    })
    .unwrap();
    assert_eq!(report.status, ReviewStatus::ChangesRequired);
    assert!(!report.findings.is_empty());
    (target, directory, scope, report)
}

#[test]
fn routes_unpublished_candidate_findings_without_accepting_or_publishing_failed_code() {
    let (target, _directory, scope, report) = failed_candidate();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let original = store.load().unwrap().unwrap();
    let head = candidate::head(root).unwrap();
    let fingerprint = fingerprint::repository_fingerprint(root).unwrap();
    let report_bytes = fs::read(&report.report_path).unwrap();
    assert!(!integrated_path(root).exists());
    let finding = &report.findings[0];

    rework_with_report(
        root.into(),
        &finding.id,
        scope.clone(),
        Some(report.report_path.clone()),
    )
    .unwrap();

    let routed = store.load().unwrap().unwrap();
    assert_eq!(
        routed.active_issue.as_ref().unwrap().id,
        original.active_issue.as_ref().unwrap().id
    );
    assert_eq!(
        routed.source_review_rework[&scope.binding_key()].findings[&finding.id].file,
        finding.file
    );
    assert_eq!(
        routed.worker_bindings[&scope.binding_key()].rework_generation,
        original.worker_bindings[&scope.binding_key()].rework_generation + 1
    );
    assert_eq!(candidate::head(root).unwrap(), head);
    assert_eq!(
        fingerprint::repository_fingerprint(root).unwrap(),
        fingerprint
    );
    assert!(!root.join("src/oversized.rs").exists());
    assert!(!integrated_path(root).exists());
    assert_eq!(fs::read(&report.report_path).unwrap(), report_bytes);

    // A repeated callback must not supersede the repair dispatch it created.
    rework_with_report(root.into(), &finding.id, scope, Some(report.report_path)).unwrap();
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        serde_json::to_value(routed).unwrap()
    );
}

#[test]
fn stale_candidate_rework_does_not_change_workflow() {
    for change in [
        "candidate_code",
        "candidate_head",
        "canonical_head",
        "canonical_code",
        "runtime",
        "recording",
        "workflow",
    ] {
        let (target, _directory, scope, report) = failed_candidate();
        let root = target.path();
        let store = RewriteStore::new(root).unwrap();
        match change {
            "candidate_code" => fs::write(
                report.worktree.join("src/oversized.rs"),
                "// changed after review\n",
            )
            .unwrap(),
            "candidate_head" => git(
                &report.worktree,
                &["commit", "--allow-empty", "-qm", "new candidate identity"],
            ),
            "canonical_head" => git(
                root,
                &["commit", "--allow-empty", "-qm", "new canonical base"],
            ),
            "canonical_code" => {
                fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 3 }\n").unwrap()
            }
            "runtime" => fs::write(
                root.join(".traffic-e2e/local/target.env"),
                "SOURCE_INPUT=changed\n",
            )
            .unwrap(),
            "recording" | "workflow" => {
                let mut state = store.load().unwrap().unwrap();
                if change == "recording" {
                    state.recording_run_id.push_str("-new");
                } else {
                    state.workflow_id.push_str("-new");
                }
                store.save(&state).unwrap();
            }
            _ => unreachable!(),
        }
        let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
        let error = rework_with_report(
            root.into(),
            &report.findings[0].id,
            scope,
            Some(report.report_path),
        )
        .unwrap_err();
        assert!(error.to_string().contains("changed"), "{change}: {error:#}");
        assert_eq!(
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
            before,
            "{change}"
        );
        assert!(!integrated_path(root).exists());
    }
}

#[test]
fn candidate_rework_requires_a_failing_report_and_an_existing_source_finding() {
    let (target, _directory, scope, mut report) = failed_candidate();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    assert!(
        rework_with_report(
            root.into(),
            "absent",
            scope.clone(),
            Some(report.report_path.clone())
        )
        .unwrap_err()
        .to_string()
        .contains("finding is absent")
    );
    report.status = ReviewStatus::Passed;
    write_json(&report.report_path, &report).unwrap();
    assert!(
        rework_with_report(
            root.into(),
            &report.findings[0].id,
            scope,
            Some(report.report_path)
        )
        .unwrap_err()
        .to_string()
        .contains("does not require rework")
    );
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    assert!(!integrated_path(root).exists());
}
