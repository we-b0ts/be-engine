use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::dns_mock::DomainMatcher;

struct Fixture {
    directory: TempDir,
    project: PathBuf,
    rules: PathBuf,
    snapshot_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let snapshot_dir = directory.path().join("snapshot");
        fs::create_dir(&snapshot_dir).unwrap();
        snapshot(
            &snapshot_dir,
            "static.config+3+config+cloud+rediscounter+user+usercounter",
            "usercounter",
            "counter.example.com:7917,shared.example.com:7917",
        );
        snapshot(
            &snapshot_dir,
            "static.config+3+config+cloud+redis+user+other",
            "other",
            "other.example.com:6379,shared.example.com:6379",
        );
        let managed = directory.path().join(".traffic-e2e");
        fs::create_dir(&managed).unwrap();
        let project = managed.join("project.yaml");
        let rules = managed.join("policy.yaml");
        fs::write(
            &project,
            format!(
                "project:\n  policy: .traffic-e2e/policy.yaml\nrecorder:\n  dns_mock:\n    enabled: true\n    bypass_strategies:\n    - strategy: breeze\n      snapshot_dir: {}\n  tcp_gateway:\n    enabled: true\n",
                snapshot_dir.display()
            ),
        )
        .unwrap();
        fs::write(&rules, SourceTrafficPolicyConfig::empty().render().unwrap()).unwrap();
        Self {
            directory,
            project,
            rules,
            snapshot_dir,
        }
    }

    fn feedback(&self) -> BreezeResourceCaptureFeedback {
        BreezeResourceCaptureFeedback {
            project_config_path: self.project.clone(),
            rules_path: self.rules.clone(),
            resource: "usercounter".to_string(),
            source_revision: "abc123".to_string(),
            source_evidence: "src/UserCounter.java:load uses usercounter".to_string(),
        }
    }

    fn endpoint_feedback(&self, endpoint: &str) -> BreezeEndpointCaptureFeedback {
        BreezeEndpointCaptureFeedback {
            project_config_path: self.project.clone(),
            rules_path: self.rules.clone(),
            endpoint: endpoint.to_string(),
            source_revision: "abc123".to_string(),
            source_evidence: "src/UserCounter.java:load resolves the counter backend".to_string(),
        }
    }
}

fn snapshot(directory: &Path, identity: &str, name: &str, backends: &str) {
    fs::write(
        directory.join(identity),
        format!("123\n{name}\nbackends:\n- {backends}\n"),
    )
    .unwrap();
}

#[test]
fn plans_and_applies_canonical_resource_to_source_traffic_policy() {
    let fixture = Fixture::new();
    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().resource, "usercounter");
    assert_eq!(
        plan.report().bypassed_domains_before,
        ["counter.example.com", "shared.example.com"]
    );
    assert_eq!(plan.report().shared_domain_resources.len(), 1);
    let report = plan.apply().unwrap();

    let rules = SourceTrafficPolicyConfig::load(&fixture.rules).unwrap();
    assert_eq!(rules.breeze_capture.len(), 1);
    assert_eq!(
        rules.breeze_capture[0].capture_resources,
        vec![report.resource_identity.clone()]
    );
    let config = AppConfig::load(&fixture.project).unwrap();
    let matcher = DomainMatcher::from_config(&config.dns_mock).unwrap();
    assert!(!matcher.matches("counter.example.com"));
    assert!(!matcher.matches("shared.example.com"));
    assert!(matcher.matches("other.example.com"));
    let reused = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    assert!(!reused.report().changed);
    assert!(reused.report().bypassed_domains_before.is_empty());
}

#[test]
fn resolves_endpoint_and_rejects_unknown_shared_or_literal_hosts() {
    let fixture = Fixture::new();
    let plan = plan_breeze_endpoint_capture(fixture.endpoint_feedback("COUNTER.EXAMPLE.COM.:7917"))
        .unwrap();
    assert_eq!(plan.report().resource, "usercounter");

    assert!(
        plan_breeze_endpoint_capture(fixture.endpoint_feedback("missing.example.com:7917"))
            .unwrap_err()
            .to_string()
            .contains("does not belong")
    );
    assert!(
        plan_breeze_endpoint_capture(fixture.endpoint_feedback("shared.example.com"))
            .unwrap_err()
            .to_string()
            .contains("shared by multiple")
    );
    assert_eq!(
        plan_breeze_endpoint_capture(fixture.endpoint_feedback("shared.example.com:6379"))
            .unwrap()
            .report()
            .resource,
        "other"
    );
    assert!(
        plan_breeze_endpoint_capture(fixture.endpoint_feedback("10.0.0.1:7917"))
            .unwrap_err()
            .to_string()
            .contains("IP literals")
    );
}

#[test]
fn rejects_ip_only_or_ambiguous_resource() {
    let fixture = Fixture::new();
    snapshot(&fixture.snapshot_dir, "ip-only", "ip-only", "10.0.0.1:6379");
    let mut ip = fixture.feedback();
    ip.resource = "ip-only".to_string();
    assert!(
        plan_breeze_resource_capture(ip)
            .unwrap_err()
            .to_string()
            .contains("IP literals are not part")
    );

    snapshot(
        &fixture.snapshot_dir,
        "duplicate-usercounter",
        "usercounter",
        "duplicate.example.com:7917",
    );
    assert!(
        plan_breeze_resource_capture(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
}

#[test]
fn apply_rejects_stale_project_policy_or_snapshot() {
    let fixture = Fixture::new();
    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    fs::write(&fixture.rules, "version: 1\n").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("source traffic policy changed")
    );

    let fixture = Fixture::new();
    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    fs::write(&fixture.project, "dns_mock: {}\n").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("config changed")
    );

    let fixture = Fixture::new();
    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    fs::write(
        fixture
            .snapshot_dir
            .join("static.config+3+config+cloud+rediscounter+user+usercounter"),
        "124\nusercounter\nbackends:\n- changed.example.com:7917\n",
    )
    .unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("snapshot resource changed")
    );
    assert!(fixture.directory.path().exists());
}
