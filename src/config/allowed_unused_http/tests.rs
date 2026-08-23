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

fn feedback(fixture: &Fixture, hosts: &[&str]) -> AllowedUnusedHttpHostFeedback {
    AllowedUnusedHttpHostFeedback {
        project_config_path: fixture.project.clone(),
        rules_path: fixture.rules.clone(),
        hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
    }
}

#[test]
fn plan_updates_the_source_traffic_policy_and_apply_converges() {
    let fixture = Fixture::new(SourceTrafficPolicyConfig::empty());
    let plan = plan_allowed_unused_http_hosts(feedback(
        &fixture,
        &["cs.aliyuncs.com", "location-readonly.aliyuncs.com"],
    ))
    .unwrap();

    assert!(plan.report().changed);
    assert_eq!(
        plan.report().added,
        vec![
            "cs.aliyuncs.com".to_string(),
            "location-readonly.aliyuncs.com".to_string()
        ]
    );
    assert!(plan.report().diff.contains("allowed_unused_http_hosts"));
    plan.apply().unwrap();

    assert_eq!(fs::read_to_string(&fixture.project).unwrap(), PROJECT);
    let effective = AppConfig::load(&fixture.project).unwrap();
    assert_eq!(
        effective.http_gateway.allowed_unused_http_hosts,
        vec![
            "cs.aliyuncs.com".to_string(),
            "location-readonly.aliyuncs.com".to_string()
        ]
    );
    let repeated = plan_allowed_unused_http_hosts(feedback(
        &fixture,
        &["location-readonly.aliyuncs.com", "cs.aliyuncs.com"],
    ))
    .unwrap();
    assert!(!repeated.report().changed);
}

#[test]
fn plan_adds_to_existing_values_and_deduplicates_input() {
    let mut rules = SourceTrafficPolicyConfig::empty();
    rules.http.allowed_unused_http_hosts = vec!["cs.aliyuncs.com".to_string()];
    let fixture = Fixture::new(rules);

    let plan = plan_allowed_unused_http_hosts(feedback(
        &fixture,
        &[
            "location-readonly.aliyuncs.com",
            "location-readonly.aliyuncs.com",
        ],
    ))
    .unwrap();

    assert_eq!(plan.report().added, vec!["location-readonly.aliyuncs.com"]);
    plan.apply().unwrap();
    assert_eq!(
        AppConfig::load(&fixture.project)
            .unwrap()
            .http_gateway
            .allowed_unused_http_hosts,
        vec![
            "cs.aliyuncs.com".to_string(),
            "location-readonly.aliyuncs.com".to_string()
        ]
    );
}

#[test]
fn rejects_noncanonical_hosts() {
    for host in [
        "CS.aliyuncs.com",
        "cs.aliyuncs.com.",
        "cs.aliyuncs.com:443",
        "*.aliyuncs.com",
    ] {
        let fixture = Fixture::new(SourceTrafficPolicyConfig::empty());
        let error = plan_allowed_unused_http_hosts(feedback(&fixture, &[host])).unwrap_err();
        assert!(error.to_string().contains("allowed unused HTTP host"));
    }
}

#[test]
fn apply_detects_project_or_rules_changes_after_plan() {
    let fixture = Fixture::new(SourceTrafficPolicyConfig::empty());
    let plan = plan_allowed_unused_http_hosts(feedback(&fixture, &["cs.aliyuncs.com"])).unwrap();
    fs::write(&fixture.rules, "version: 1\n").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("changed after planning")
    );

    let fixture = Fixture::new(SourceTrafficPolicyConfig::empty());
    let plan = plan_allowed_unused_http_hosts(feedback(&fixture, &["cs.aliyuncs.com"])).unwrap();
    fs::write(&fixture.project, format!("{PROJECT}# concurrent edit\n")).unwrap();
    assert!(
        plan.apply()
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
    fn new(rules: SourceTrafficPolicyConfig) -> Self {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project.yaml");
        let rules_path = temp.path().join("source-traffic-policy.yaml");
        fs::write(&project, PROJECT).unwrap();
        fs::write(&rules_path, rules.render().unwrap()).unwrap();
        Self {
            _temp: temp,
            project,
            rules: rules_path,
        }
    }
}
