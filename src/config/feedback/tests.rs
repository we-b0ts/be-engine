use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

use super::*;

const PROJECT: &str = r#"project:
  recording:
    source_traffic_policy: source-traffic-policy.yaml
recorder:
  http_gateway:
    enabled: true
    rules:
    - name: first
      path_prefixes: [/first]
    - name: pluto
      path_prefixes: [/api]
  recording:
    access_policy: unrestricted
"#;

fn feedback(fixture: &Fixture, authority: CasePathPatternAuthority) -> CasePathPatternFeedback {
    CasePathPatternFeedback {
        project_config_path: fixture.project.clone(),
        rules_path: fixture.rules.clone(),
        source_revision: "abc123".to_string(),
        case_source: "/recordings/focused".to_string(),
        authority,
        patterns: vec!["/api/huaweiyun/loadbalancers/listeners/list/*".to_string()],
        incorrect_patterns: Vec::new(),
        correction_evidence: None,
    }
}

#[test]
fn focused_feedback_updates_only_source_traffic_policy_and_converges() {
    let fixture = Fixture::new(&["/api/xufei/getone/*"]);
    let plan =
        plan_case_path_pattern_feedback(feedback(&fixture, CasePathPatternAuthority::Focused))
            .unwrap();
    assert_eq!(
        plan.report().added,
        vec!["/api/huaweiyun/loadbalancers/listeners/list/*"]
    );
    assert!(plan.report().removed.is_empty());
    plan.apply(false).unwrap();

    assert_eq!(fs::read_to_string(&fixture.project).unwrap(), PROJECT);
    let effective = AppConfig::load(&fixture.project).unwrap();
    assert_eq!(
        effective.http_gateway.case_path_patterns,
        vec![
            "/api/huaweiyun/loadbalancers/listeners/list/*".to_string(),
            "/api/xufei/getone/*".to_string()
        ]
    );
    let rules = SourceTrafficPolicyConfig::load(&fixture.rules).unwrap();
    assert_eq!(rules.http.source_revision, "abc123");
}

#[test]
fn no_candidates_is_a_no_op() {
    let fixture = Fixture::new(&["/api/xufei/getone/*"]);
    let mut request = feedback(&fixture, CasePathPatternAuthority::Focused);
    request.patterns.clear();
    let plan = plan_case_path_pattern_feedback(request).unwrap();
    assert!(plan.report().no_candidates);
    assert!(!plan.report().changed);
    assert!(plan.report().diff.is_empty());
}

#[test]
fn explicit_correction_requires_evidence_and_delete_authorization() {
    let fixture = Fixture::new(&["/api/xufei/getone/*"]);
    let mut correction = feedback(&fixture, CasePathPatternAuthority::Focused);
    correction.patterns.clear();
    correction.incorrect_patterns = vec!["/api/xufei/getone/*".to_string()];
    assert!(
        plan_case_path_pattern_feedback(correction.clone())
            .unwrap_err()
            .to_string()
            .contains("--correction-evidence")
    );
    correction.correction_evidence = Some("router.go@abc123 has only a static route".to_string());
    let plan = plan_case_path_pattern_feedback(correction.clone()).unwrap();
    assert_eq!(plan.report().removed, vec!["/api/xufei/getone/*"]);
    assert!(
        plan.apply(false)
            .unwrap_err()
            .to_string()
            .contains("--allow-delete")
    );
    plan_case_path_pattern_feedback(correction)
        .unwrap()
        .apply(true)
        .unwrap();
    assert!(
        AppConfig::load(&fixture.project)
            .unwrap()
            .http_gateway
            .case_path_patterns
            .is_empty()
    );
}

#[test]
fn rejects_invalid_or_out_of_scope_patterns() {
    let fixture = Fixture::new(&[]);
    let mut invalid = feedback(&fixture, CasePathPatternAuthority::Focused);
    invalid.patterns = vec!["/api/users/user-*".to_string()];
    assert!(
        plan_case_path_pattern_feedback(invalid)
            .unwrap_err()
            .to_string()
            .contains("whole path segment")
    );
    let mut outside = feedback(&fixture, CasePathPatternAuthority::Focused);
    outside.patterns = vec!["/other/users/*".to_string()];
    assert!(
        plan_case_path_pattern_feedback(outside)
            .unwrap_err()
            .to_string()
            .contains("outside")
    );
    let mut non_trailing = feedback(&fixture, CasePathPatternAuthority::Focused);
    non_trailing.patterns = vec!["/api/namespaces/**/pods".to_string()];
    assert!(
        plan_case_path_pattern_feedback(non_trailing)
            .unwrap_err()
            .to_string()
            .contains("final path segment")
    );
}

#[test]
fn apply_detects_concurrent_rule_changes() {
    let fixture = Fixture::new(&[]);
    let plan =
        plan_case_path_pattern_feedback(feedback(&fixture, CasePathPatternAuthority::Focused))
            .unwrap();
    fs::write(&fixture.rules, "version: 1\n").unwrap();
    assert!(
        plan.apply(false)
            .unwrap_err()
            .to_string()
            .contains("changed after planning")
    );
}

struct Fixture {
    _temp: TempDir,
    project: PathBuf,
    rules: PathBuf,
}

impl Fixture {
    fn new(patterns: &[&str]) -> Self {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project.yaml");
        let rules_path = temp.path().join("source-traffic-policy.yaml");
        fs::write(&project, PROJECT).unwrap();
        let mut rules = SourceTrafficPolicyConfig::empty();
        rules.http.source_revision = "old".to_string();
        rules.http.case_path_patterns = patterns.iter().map(|value| (*value).to_string()).collect();
        fs::write(&rules_path, rules.render().unwrap()).unwrap();
        Self {
            _temp: temp,
            project,
            rules: rules_path,
        }
    }
}
