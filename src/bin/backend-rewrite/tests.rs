use super::*;
use clap::CommandFactory;

#[test]
fn exposes_only_the_rewrite_coordinator_surface() {
    let command = Cli::command();
    command.clone().debug_assert();
    let visible = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| subcommand.get_name())
        .collect::<Vec<_>>();
    assert_eq!(
        visible,
        [
            "next",
            "status",
            "inventory",
            "case",
            "evidence",
            "rule",
            "dependency-rule",
            "route",
            "repair",
            "recording",
            "recover",
        ]
    );
}

#[test]
fn compact_json_is_default_and_pretty_is_explicit() {
    let value = serde_json::json!({"status": "ok", "items": [1, 2]});
    let mut compact = Vec::new();
    write_json(&mut compact, &value, false).unwrap();
    assert_eq!(compact.iter().filter(|byte| **byte == b'\n').count(), 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&compact).unwrap(),
        value
    );

    let mut pretty = Vec::new();
    write_json(&mut pretty, &value, true).unwrap();
    assert!(pretty.iter().filter(|byte| **byte == b'\n').count() > 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&pretty).unwrap(),
        value
    );
    assert!(Cli::try_parse_from(["test", "--pretty", "status"]).is_ok());
    assert!(Cli::try_parse_from(["test", "status", "--pretty"]).is_ok());
}

#[test]
fn parses_the_bounded_rewrite_surface() {
    assert!(
        Cli::try_parse_from([
            "test",
            "next",
            "--api",
            "GET /api/users/*",
            "--source-route",
            "/api/users/:id",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "recording",
            "request",
            "--kind",
            "standard",
            "--reason",
            "user-requested",
            "--api",
            "GET /api/widgets/*",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "recording",
            "request",
            "--kind",
            "standard",
            "--reason",
            "user-requested",
            "--replace-pending",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from(["test", "recording", "execute", "recording-0123456789abcdef",])
            .is_ok()
    );
    assert!(Cli::try_parse_from(["test", "evidence", "evq-r1-issue-representatives"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "case",
            "dependencies",
            "/repo/.traffic-e2e/artifacts/run/api/case-a",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "case",
            "dependencies",
            "/repo/.traffic-e2e/artifacts/run/api/case-a",
            "dependency-target-0123456789abcdef",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "route",
            "--kind",
            "replay-capability-gap",
            "--evidence-id",
            "evidence-1",
            "--source-ref",
            "src/client.rs:42",
            "--required-change",
            "support source-equivalent request matching",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "route",
            "--kind",
            "replay-capability-gap",
            "--evidence-id",
            "evidence-1",
            "--source-ref",
            "src/client.rs:42",
            "--required-change",
            "support source-equivalent request matching",
            "--acceptance-command",
            "backend-rewrite next",
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["test", "repair", "verify", "repair-1"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "recording",
            "request",
            "--kind",
            "standard",
            "--reason",
            "user-requested",
            "--duration-seconds",
            "90",
            "--per-api-case-limit",
            "250",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "recording",
            "request",
            "--kind",
            "standard",
            "--reason",
            "user-requested",
            "--per-api-case-limit",
            "0",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "dependency-rule",
            "plan",
            "memcached",
            "--evidence-id",
            "evidence-1",
            "--name",
            "planet-video-cache-warm",
            "--source-evidence",
            "TopUserServiceImpl.java:691 scheduled cache warm",
            "--breeze-resource",
            "user-video",
            "--key-start",
            "0",
            "--key-end",
            "4095",
            "--key-suffix",
            "pl_video",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "dependency-rule",
            "plan",
            "memcached",
            "--evidence-id",
            "evidence-1",
            "--name",
            "cache-warm",
            "--source-evidence",
            "src/cache.rs:init",
            "--breeze-resource",
            "user-video",
            "--key-start",
            "0",
            "--key-end",
            "1",
            "--key-suffix",
            "warm",
            "--authority",
            "config.internal",
        ])
        .is_err()
    );
}

#[test]
fn dependency_rule_help_is_protocol_specific_and_has_no_api_context() {
    let memcached = Cli::try_parse_from(["test", "dependency-rule", "plan", "memcached", "--help"])
        .unwrap_err()
        .to_string();
    assert!(memcached.contains("--breeze-resource"));
    assert!(memcached.contains("--key-start"));
    assert!(!memcached.contains("--authority"));
    assert!(!memcached.contains("--api"));
    assert!(!memcached.contains("--case-source"));
    assert!(!memcached.contains("--source-revision"));

    let http = Cli::try_parse_from(["test", "dependency-rule", "plan", "http", "--help"])
        .unwrap_err()
        .to_string();
    assert!(http.contains("--authority"));
    assert!(http.contains("--path-prefix"));
    assert!(!http.contains("--breeze-resource"));
    assert!(!http.contains("--key-start"));

    let zcount = Cli::try_parse_from([
        "test",
        "dependency-rule",
        "plan",
        "redis",
        "zcount",
        "--help",
    ])
    .unwrap_err()
    .to_string();
    assert!(zcount.contains("--key-prefix"));
    assert!(!zcount.contains("--key <"));
    assert!(!zcount.contains("--initial-load-timeout-ms"));

    let get = Cli::try_parse_from(["test", "dependency-rule", "plan", "redis", "get", "--help"])
        .unwrap_err()
        .to_string();
    assert!(get.contains("--key <"));
    assert!(get.contains("--initial-load-timeout-ms"));
    assert!(!get.contains("--key-prefix"));

    for command in ["scard", "hgetall"] {
        let help = Cli::try_parse_from([
            "test",
            "dependency-rule",
            "plan",
            "redis",
            command,
            "--help",
        ])
        .unwrap_err()
        .to_string();
        assert!(help.contains("--key <"));
        assert!(help.contains("--initial-load-timeout-ms"));
        assert!(!help.contains("--key-prefix"));
        assert!(!help.contains("--command"));
    }
}
