use super::*;
use std::path::Path;

pub(super) const POLICY: &str = r#"{
    "case-limit": 200,
    "includes": [{"path":"/api/teams/:id/skills","match":"exact"}, {"path":"/files/*rest","match":"exact"}],
    "excludes": [{"path":"/internal"}]
}"#;

fn options(path: &Path) -> RecordOptions {
    OptionsCli::try_parse_from([
        "test".as_ref(),
        "--coordination".as_ref(),
        "redis".as_ref(),
        "--redis-url".as_ref(),
        "redis://127.0.0.1:6379/0".as_ref(),
        "--advertise-url".as_ref(),
        "http://recorder:4080".as_ref(),
        "--api-policy".as_ref(),
        path.as_os_str(),
        "--case-limit".as_ref(),
        "2".as_ref(),
        "--".as_ref(),
        "true".as_ref(),
    ])
    .unwrap()
    .options
}

#[test]
fn gateway_policy_does_not_override_recorder_capture_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("api-policy.json");
    std::fs::write(&path, POLICY).unwrap();
    let options = options(&path);
    let policy = options.load_api_policy().unwrap().unwrap();
    let published: serde_json::Value = serde_json::from_str(&policy.json).unwrap();
    assert_eq!(published["case-limit"], 200);
    assert_eq!(published["includes"][0]["path"], "/api/teams/:id/skills");
    assert_eq!(published["excludes"][0]["match"], "prefix");
    let config = options.config().unwrap();
    assert_eq!(config.http_gateway.per_api_case_limits.default, 2);
    assert!(config.http_gateway.case_path_patterns.is_empty());
    assert!(config.http_gateway.rules.is_empty());
    assert!(config.http_gateway.exclude_rules.is_empty());
}

#[test]
fn missing_or_invalid_gateway_policy_fails_before_connecting() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("api-policy.json");
    assert!(options(&path).load_api_policy().is_err());
    assert!(options(temp.path()).load_api_policy().is_err());
    for json in [
        "not json",
        "[]",
        "null",
        r#"{"case-limit":-1}"#,
        r#"{"case-limit":9223372036854775808}"#,
        r#"{"case-limit":"200"}"#,
        r#"{"includes":[{"path":"relative"}]}"#,
        r#"{"includes":[{"path":"/api?query=1"}]}"#,
        r#"{"includes":[{"path":"/api#fragment","match":"exact"}]}"#,
        r#"{"includes":[{"path":"/api/:id"}]}"#,
        r#"{"includes":[{"path":"/api/*rest/tail","match":"exact"}]}"#,
        r#"{"includes":[{"path":"/api","match":"all"}]}"#,
        r#"{"includes":[{"path":"/api","case-limit":3}]}"#,
        r#"{"excludes":[{"path":"/api/:id"}]}"#,
        r#"{"unknown":1}"#,
    ] {
        std::fs::write(&path, json).unwrap();
        assert!(options(&path).load_api_policy().is_err(), "accepted {json}");
    }
    for json in [
        "{}",
        r#"{"case-limit":0}"#,
        r#"{"includes":[{"path":"/"}]}"#,
    ] {
        std::fs::write(&path, json).unwrap();
        assert!(options(&path).load_api_policy().is_ok(), "rejected {json}");
    }
}

#[test]
fn coordination_reserves_policy_and_reservation_keys() {
    assert!(
        OptionsCli::try_parse_from(["test", "--api-policy", "policy.json", "--", "true"]).is_err()
    );
    let direct = OptionsCli::try_parse_from(["test", "--", "true"]).unwrap();
    assert!(direct.options.load_api_policy().unwrap().is_none());
    for suffix in ["api-policy", "api-counts", "inflight", "inflight:legacy"] {
        let mut options = options(Path::new("policy.json"));
        options.url_key = Some(format!("{}:{suffix}", options.prefix));
        assert!(options.config().is_err());
    }
}
