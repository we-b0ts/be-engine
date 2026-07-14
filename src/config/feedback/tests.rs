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
fn authoritative_removal_requires_explicit_allow_delete() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let plan =
        plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Authoritative))
            .unwrap();
    assert_eq!(plan.report().removed, vec!["/api/xufei/getone/*"]);
    let error = plan.apply(false).unwrap_err();
    assert!(error.to_string().contains("--allow-delete"));
    assert_eq!(fs::read_to_string(&path).unwrap(), CONFIG);

    let plan =
        plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Authoritative))
            .unwrap();
    plan.apply(true).unwrap();
    let updated = fs::read_to_string(&path).unwrap();
    assert!(!updated.contains("/api/xufei/getone/*"));
}

#[test]
fn focused_feedback_rejects_allow_delete() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("recorder.toml");
    fs::write(&path, CONFIG).unwrap();

    let plan = plan_case_path_pattern_feedback(feedback(&path, CasePathPatternAuthority::Focused))
        .unwrap();
    let error = plan.apply(true).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires --authority authoritative")
    );
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
