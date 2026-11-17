use super::config::{ExpectedResponseUsage, validate_replay_policy};
use std::{fs, path::Path};
use tempfile::TempDir;

#[test]
fn validates_unified_policy_example() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("config")
        .join("policy.example.yaml");
    let report = validate_replay_policy(&path).unwrap();

    assert_eq!(report.version, 1);
    assert!(report.runner_owned_response_assertions);
}

#[test]
fn rejects_removed_version_two_policy_contract() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("policy.yaml");
    fs::write(
        &path,
        "version: 2\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();

    let error = validate_replay_policy(&path).unwrap_err();
    assert!(format!("{error:#}").contains("traffic-policy/v3"));
}

#[test]
fn rejects_legacy_rules_key() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("policy.yaml");
    fs::write(
        &path,
        "version: 3\nexpected_response: assertions_only\nrules: []\n",
    )
    .unwrap();

    let error = validate_replay_policy(&path).unwrap_err();
    assert!(format!("{error:#}").contains("traffic-policy/v3"));
}

#[test]
fn validates_assertion_only_policy_contract() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("replay.yaml");
    crate::policy::runtime::write_policy_fixture(
        &path,
        r#"
version: 1
expected_response: assertions_only
dependency_rules: []
"#,
    )
    .unwrap();

    let report = validate_replay_policy(&path).unwrap();
    assert_eq!(report.version, 1);
    assert_eq!(
        report.expected_response,
        ExpectedResponseUsage::AssertionsOnly
    );
    assert!(report.dependency_rule_ids.is_empty());
    assert!(report.fingerprint.starts_with("sha256:"));
}

#[test]
fn rejects_policy_without_expected_response_contract() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("replay.yaml");
    fs::write(&path, "version: 1\ndependency_rules: []\n").unwrap();

    let error = validate_replay_policy(&path).unwrap_err();
    assert!(error.to_string().contains("traffic-policy/v3"));
}
