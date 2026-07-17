use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::*;
use crate::config::AppConfig;

const CONFIG: &str = r#"# keep this comment
[http_gateway]
enabled = true

[[http_gateway.rules]]
name = "first"
path_prefixes = ["/first"]

[[http_gateway.rules]]
name = "pluto"
path_prefixes = ["/api"]
case_path_patterns = []
headers = {}

[recording]
access_policy = "unrestricted"
"#;

fn feedback(path: &Path, hosts: &[&str]) -> AllowedUnusedHttpHostFeedback {
    AllowedUnusedHttpHostFeedback {
        config_path: path.to_path_buf(),
        rule_name: "pluto".to_string(),
        hosts: hosts.iter().map(|host| (*host).to_string()).collect(),
    }
}

#[test]
fn plan_bootstraps_managed_block_and_apply_converges() {
    let fixture = Fixture::new(CONFIG);
    let plan = plan_allowed_unused_http_hosts(feedback(
        &fixture.path,
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
    assert!(
        plan.report()
            .diff
            .contains("+allowed_unused_http_hosts = [")
    );

    let applied = plan.apply().unwrap();
    assert!(applied.applied);
    let updated = fs::read_to_string(&fixture.path).unwrap();
    assert!(updated.starts_with("# keep this comment\n"));
    assert!(updated.contains(BEGIN_MARKER));
    assert!(updated.find(BEGIN_MARKER).unwrap() < updated.find("headers = {}").unwrap());
    let config = AppConfig::load(&fixture.path).unwrap();
    assert_eq!(
        config.http_gateway.rules[1].allowed_unused_http_hosts,
        vec![
            "cs.aliyuncs.com".to_string(),
            "location-readonly.aliyuncs.com".to_string()
        ]
    );

    let repeated = plan_allowed_unused_http_hosts(feedback(
        &fixture.path,
        &["location-readonly.aliyuncs.com", "cs.aliyuncs.com"],
    ))
    .unwrap();
    assert!(!repeated.report().changed);
    assert!(repeated.report().added.is_empty());
}

#[test]
fn plan_adds_hosts_to_existing_managed_block_and_deduplicates_input() {
    let fixture = Fixture::new(&CONFIG.replace(
        "headers = {}",
        r#"# BEGIN AI-MANAGED ALLOWED UNUSED HTTP HOSTS
allowed_unused_http_hosts = [
  "cs.aliyuncs.com",
]
# END AI-MANAGED ALLOWED UNUSED HTTP HOSTS
headers = {}"#,
    ));
    let plan = plan_allowed_unused_http_hosts(feedback(
        &fixture.path,
        &[
            "location-readonly.aliyuncs.com",
            "location-readonly.aliyuncs.com",
        ],
    ))
    .unwrap();

    assert_eq!(plan.report().added, vec!["location-readonly.aliyuncs.com"]);
    plan.apply().unwrap();
    let config = AppConfig::load(&fixture.path).unwrap();
    assert_eq!(
        config.http_gateway.rules[1].allowed_unused_http_hosts,
        vec![
            "cs.aliyuncs.com".to_string(),
            "location-readonly.aliyuncs.com".to_string()
        ]
    );
}

#[test]
fn plan_rejects_unmanaged_or_invalid_hosts() {
    let unmanaged = Fixture::new(&CONFIG.replace(
        "headers = {}",
        "allowed_unused_http_hosts = [\"cs.aliyuncs.com\"]\nheaders = {}",
    ));
    let error = plan_allowed_unused_http_hosts(feedback(&unmanaged.path, &["cs.aliyuncs.com"]))
        .unwrap_err();
    assert!(error.to_string().contains("AI-managed block"));

    for host in [
        "CS.aliyuncs.com",
        "cs.aliyuncs.com.",
        "cs.aliyuncs.com:443",
        "*.aliyuncs.com",
    ] {
        let fixture = Fixture::new(CONFIG);
        let error = plan_allowed_unused_http_hosts(feedback(&fixture.path, &[host])).unwrap_err();
        assert!(error.to_string().contains("allowed unused HTTP host"));
    }
}

#[test]
fn apply_detects_config_changes_after_plan() {
    let fixture = Fixture::new(CONFIG);
    let plan =
        plan_allowed_unused_http_hosts(feedback(&fixture.path, &["cs.aliyuncs.com"])).unwrap();
    fs::write(&fixture.path, format!("{CONFIG}\n# concurrent edit\n")).unwrap();

    let error = plan.apply().unwrap_err();

    assert!(error.to_string().contains("changed after planning"));
}

#[test]
fn config_rejects_hosts_on_exclude_rules_and_duplicates() {
    let duplicate = CONFIG.replace(
        "headers = {}",
        "allowed_unused_http_hosts = [\"cs.aliyuncs.com\", \"cs.aliyuncs.com\"]\nheaders = {}",
    );
    let config: AppConfig = toml::from_str(&duplicate).unwrap();
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );

    let exclude = CONFIG.replace(
        "path_prefixes = [\"/first\"]",
        "path_prefixes = [\"/first\"]\nallowed_unused_http_hosts = [\"cs.aliyuncs.com\"]",
    );
    let config: AppConfig = toml::from_str(&exclude).unwrap();
    config.validate().unwrap();

    let exclude = r#"
[http_gateway]
[[http_gateway.exclude_rules]]
name = "health"
allowed_unused_http_hosts = ["cs.aliyuncs.com"]
"#;
    let config: AppConfig = toml::from_str(exclude).unwrap();
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("exclude_rules")
    );
}

struct Fixture {
    _temp: TempDir,
    path: PathBuf,
}

impl Fixture {
    fn new(contents: &str) -> Self {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("recorder.toml");
        fs::write(&path, contents).unwrap();
        Self { _temp: temp, path }
    }
}
