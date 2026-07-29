use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::dns_mock::DomainMatcher;

struct Fixture {
    directory: TempDir,
    config_path: PathBuf,
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
        let config_path = directory.path().join("recorder.toml");
        fs::write(
            &config_path,
            format!(
                r#"
[dns_mock]
enabled = true

[[dns_mock.bypass_strategies]]
strategy = "breeze"
snapshot_dir = "{}"

[tcp_gateway]
enabled = true
"#,
                snapshot_dir.display()
            ),
        )
        .unwrap();
        Self {
            directory,
            config_path,
            snapshot_dir,
        }
    }

    fn feedback(&self) -> BreezeResourceCaptureFeedback {
        BreezeResourceCaptureFeedback {
            config_path: self.config_path.clone(),
            resource: "usercounter".to_string(),
            source_revision: "abc123".to_string(),
            source_evidence: "src/UserCounter.java:load uses usercounter".to_string(),
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
fn plans_and_applies_unique_resource_as_canonical_identity() {
    let fixture = Fixture::new();

    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();

    assert!(plan.report().changed);
    assert!(!plan.report().applied);
    assert_eq!(plan.report().resource, "usercounter");
    assert_eq!(plan.report().domains.len(), 2);
    assert_eq!(plan.report().shared_domain_resources.len(), 1);
    assert!(
        plan.report()
            .resource_identity
            .ends_with("+rediscounter+user+usercounter")
    );
    let report = plan.apply().unwrap();
    assert!(report.applied);

    let raw = fs::read_to_string(&fixture.config_path).unwrap();
    assert!(raw.contains(BEGIN_MARKER));
    assert!(raw.contains(&report.resource_identity));
    let config = parse_and_validate(&raw, &fixture.config_path).unwrap();
    let matcher = DomainMatcher::from_config(&config.dns_mock).unwrap();
    assert!(!matcher.matches("counter.example.com"));
    assert!(!matcher.matches("shared.example.com"));
    assert!(matcher.matches("other.example.com"));

    let repeated = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    assert!(!repeated.report().changed);
}

#[test]
fn rejects_ip_only_or_ambiguous_resource() {
    let fixture = Fixture::new();
    snapshot(&fixture.snapshot_dir, "ip-only", "ip-only", "10.0.0.1:6379");
    let mut ip_feedback = fixture.feedback();
    ip_feedback.resource = "ip-only".to_string();

    let ip_error = plan_breeze_resource_capture(ip_feedback)
        .unwrap_err()
        .to_string();
    assert!(ip_error.contains("IP literals are not part of DNS bypass"));

    snapshot(
        &fixture.snapshot_dir,
        "duplicate-usercounter",
        "usercounter",
        "duplicate.example.com:7917",
    );
    let ambiguous = plan_breeze_resource_capture(fixture.feedback())
        .unwrap_err()
        .to_string();
    assert!(ambiguous.contains("ambiguous"));
    assert!(ambiguous.contains("exact descriptor identity"));
}

#[test]
fn apply_rejects_stale_config_or_snapshot() {
    let fixture = Fixture::new();
    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    fs::write(&fixture.config_path, "[dns_mock]\nenabled = false\n").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("config changed")
    );

    let fixture = Fixture::new();
    let plan = plan_breeze_resource_capture(fixture.feedback()).unwrap();
    let descriptor = fixture
        .snapshot_dir
        .join("static.config+3+config+cloud+rediscounter+user+usercounter");
    fs::write(
        descriptor,
        "124\nusercounter\nbackends:\n- changed.example.com:7917\n",
    )
    .unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("snapshot resource changed")
    );
}

#[test]
fn refuses_unmanaged_existing_capture_assignment() {
    let fixture = Fixture::new();
    let raw = fs::read_to_string(&fixture.config_path).unwrap();
    fs::write(
        &fixture.config_path,
        raw.replace(
            &format!("snapshot_dir = \"{}\"", fixture.snapshot_dir.display()),
            &format!(
                "snapshot_dir = \"{}\"\ncapture_resources = [\"other\"]",
                fixture.snapshot_dir.display()
            ),
        ),
    )
    .unwrap();

    let error = plan_breeze_resource_capture(fixture.feedback())
        .unwrap_err()
        .to_string();

    assert!(error.contains("AI-managed block"));
    assert!(fixture.directory.path().exists());
}
