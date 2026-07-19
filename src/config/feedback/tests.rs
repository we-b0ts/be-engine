use std::path::Path;
use tempfile::tempdir;

use super::*;

const CONFIG: &str = r#"# keep this comment
[http_gateway]
enabled = true

[[http_gateway.rules]]
name = "first"
path_prefixes = ["/first"]
case_path_patterns = []

[[http_gateway.rules]]
name = "pluto"
path_prefixes = ["/api"]
# BEGIN AI-MANAGED CASE PATH PATTERNS
# source_revision = "old"
case_path_patterns = [
  "/api/xufei/getone/*",
]
# END AI-MANAGED CASE PATH PATTERNS
headers = {}

[recording]
access_policy = "unrestricted"
"#;

fn feedback(path: &Path, authority: CasePathPatternAuthority) -> CasePathPatternFeedback {
    CasePathPatternFeedback {
        config_path: path.to_path_buf(),
        rule_name: "pluto".to_string(),
        source_revision: "abc123".to_string(),
        case_source: "/recordings/focused".to_string(),
        authority,
        patterns: vec!["/api/huaweiyun/loadbalancers/listeners/list/*".to_string()],
        incorrect_patterns: Vec::new(),
        correction_evidence: None,
    }
}

#[test]
fn focused_feedback_adds_without_removing_and_preserves_other_text() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let plan = plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Focused))
        .unwrap();
    assert_eq!(
        plan.report().added,
        vec!["/api/huaweiyun/loadbalancers/listeners/list/*"]
    );
    assert!(plan.report().removed.is_empty());
    assert!(plan.report().diff.contains("+  \"/api/huaweiyun"));

    let report = plan.apply(false).unwrap();
    assert!(report.applied);
    let updated = fs::read_to_string(&path).unwrap();
    assert!(updated.starts_with("# keep this comment\n"));
    assert!(updated.contains("# source_revision = \"abc123\""));
    assert!(updated.contains("/api/xufei/getone/*"));
    assert!(updated.contains("/api/huaweiyun/loadbalancers/listeners/list/*"));
    parse_and_validate(&updated, &path).unwrap();
}

#[test]
fn focused_feedback_without_candidates_is_a_no_op_plan() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();
    let mut feedback = feedback(&path, CasePathPatternAuthority::Focused);
    feedback.patterns.clear();

    let plan = plan_case_path_pattern_feedback(feedback).unwrap();

    assert!(plan.report().no_candidates);
    assert!(!plan.report().changed);
    assert!(plan.report().added.is_empty());
    assert!(plan.report().removed.is_empty());
    assert!(plan.report().diff.is_empty());
    assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG);
}

#[test]
fn authoritative_feedback_is_add_only_and_preserves_omitted_patterns() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let plan =
        plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Authoritative))
            .unwrap();
    assert!(plan.report().removed.is_empty());
    plan.apply(false).unwrap();

    let updated = fs::read_to_string(&path).unwrap();
    assert!(updated.contains("/api/xufei/getone/*"));
    assert!(updated.contains("/api/huaweiyun/loadbalancers/listeners/list/*"));
}

#[test]
fn allow_delete_without_an_explicit_correction_is_rejected() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let plan = plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Focused))
        .unwrap();
    let error = plan.apply(true).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires at least one explicit --remove-incorrect-pattern")
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG);
}

#[test]
fn explicit_incorrect_pattern_requires_evidence_and_allow_delete() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();
    let mut correction = feedback(&path, CasePathPatternAuthority::Focused);
    correction.patterns.clear();
    correction.incorrect_patterns = vec!["/api/xufei/getone/*".to_string()];

    let error = plan_case_path_pattern_feedback(correction.clone()).unwrap_err();
    assert!(error.to_string().contains("--correction-evidence"));

    correction.correction_evidence =
        Some("router.go@abc123 has only the static route /api/xufei/getone".to_string());
    let plan = plan_case_path_pattern_feedback(correction.clone()).unwrap();
    assert_eq!(plan.report().removed, vec!["/api/xufei/getone/*"]);
    assert_eq!(
        plan.report().correction_evidence.as_deref(),
        correction.correction_evidence.as_deref()
    );
    assert_eq!(
        plan.report().corrections_requested,
        vec!["/api/xufei/getone/*"]
    );
    assert!(plan.report().corrections_already_absent.is_empty());
    let error = plan.apply(false).unwrap_err();
    assert!(error.to_string().contains("--allow-delete"));
    assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG);

    let plan = plan_case_path_pattern_feedback(correction).unwrap();
    plan.apply(true).unwrap();
    assert!(
        !fs::read_to_string(&path)
            .unwrap()
            .contains("/api/xufei/getone/*")
    );

    let mut verification = feedback(&path, CasePathPatternAuthority::Focused);
    verification.patterns.clear();
    verification.incorrect_patterns = vec!["/api/xufei/getone/*".to_string()];
    verification.correction_evidence =
        Some("router.go@abc123 has only the static route /api/xufei/getone".to_string());
    let replan = plan_case_path_pattern_feedback(verification).unwrap();
    assert!(!replan.report().changed);
    assert!(replan.report().removed.is_empty());
    assert_eq!(
        replan.report().corrections_already_absent,
        vec!["/api/xufei/getone/*"]
    );
}

#[test]
fn allow_delete_rejects_a_correction_that_is_already_absent() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();
    let mut correction = feedback(&path, CasePathPatternAuthority::Focused);
    correction.patterns.clear();
    correction.incorrect_patterns = vec!["/api/not-present/*".to_string()];
    correction.correction_evidence = Some("source route inspection".to_string());

    let plan = plan_case_path_pattern_feedback(correction).unwrap();
    assert!(plan.report().removed.is_empty());
    assert_eq!(
        plan.report().corrections_already_absent,
        vec!["/api/not-present/*"]
    );
    let error = plan.apply(true).unwrap_err();
    assert!(error.to_string().contains("--allow-delete requires"));
    assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG);
}

#[test]
fn refuses_config_without_explicit_managed_block() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG.replace(BEGIN_MARKER, "# unmanaged")).unwrap();

    let error = plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Focused))
        .unwrap_err();
    assert!(error.to_string().contains("end marker has no begin marker"));
}

#[test]
fn rejects_non_segment_wildcard_and_pattern_outside_rule() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let mut invalid = feedback(&path, CasePathPatternAuthority::Focused);
    invalid.patterns = vec!["/api/users/user-*".to_string()];
    let error = plan_case_path_pattern_feedback(invalid).unwrap_err();
    assert!(error.to_string().contains("whole path segment"));

    let mut outside = feedback(&path, CasePathPatternAuthority::Focused);
    outside.patterns = vec!["/other/users/*".to_string()];
    let error = plan_case_path_pattern_feedback(outside).unwrap_err();
    assert!(error.to_string().contains("outside"));
}

#[test]
fn accepts_only_a_trailing_catch_all() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let mut catch_all = feedback(&path, CasePathPatternAuthority::Focused);
    catch_all.patterns = vec!["/api/k8s/v1/namespaces/**".to_string()];
    let plan = plan_case_path_pattern_feedback(catch_all).unwrap();
    assert_eq!(plan.report().added, vec!["/api/k8s/v1/namespaces/**"]);

    let mut non_trailing = feedback(&path, CasePathPatternAuthority::Focused);
    non_trailing.patterns = vec!["/api/namespaces/**/pods".to_string()];
    let error = plan_case_path_pattern_feedback(non_trailing).unwrap_err();
    assert!(error.to_string().contains("final path segment"));
}

#[test]
fn apply_detects_changes_after_plan() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let plan = plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Focused))
        .unwrap();
    fs::write(&path, format!("{CONFIG}\n# concurrent edit\n")).unwrap();
    let error = plan.apply(false).unwrap_err();
    assert!(error.to_string().contains("changed after planning"));
}
