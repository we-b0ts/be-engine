use super::*;
use clap::CommandFactory;

#[test]
fn exposes_only_the_rewrite_coordinator_surface() {
    let command = Cli::command();
    command.clone().debug_assert();
    assert_eq!(command.get_version(), Some(traffic_e2e::BINARY_VERSION));
    let visible = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| subcommand.get_name())
        .collect::<Vec<_>>();
    assert_eq!(
        visible,
        [
            "init",
            "startup",
            "config",
            "next",
            "status",
            "inventory",
            "case",
            "evidence",
            "rule",
            "dependency-rule",
            "recorder-capture",
            "route",
            "repair",
            "worker",
            "verification",
            "target-quality",
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
            "init",
            "--source-container",
            "friendship",
            "--breeze",
        ])
        .is_ok()
    );
    let hessian2_unordered_path = r#"{"value_path":["result","groups","*","whiteList"],"display_path":"$.result.groups[*].whiteList","source_evidence":"src/rule.rs:whiteList is a Set"}"#;
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--evidence-id",
            "evidence-current",
            "--body-codec",
            "hessian2",
            "--unordered-path",
            hessian2_unordered_path,
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--evidence-id",
            "evidence-current",
            "--body-codec",
            "hessian2",
            "--kind",
            "unordered",
            "--json-pointer",
            "$.result.groups[*].whiteList",
            "--unordered-path",
            hessian2_unordered_path,
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--evidence-id",
            "evidence-current",
            "--body-codec",
            "json",
            "--kind",
            "uuid",
            "--json-pointer",
            "/request_id",
            "--source-evidence",
            "src/request.rs:request_id generates a UUID",
            "--source-example",
            "source-uuid",
            "--target-example",
            "target-uuid",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--evidence-id",
            "evidence-current",
            "--kind",
            "dynamic",
            "--json-pointer",
            "/request_id",
            "--source-evidence",
            "src/request.rs:request_id generation",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--evidence-id",
            "evidence-current",
            "--body-codec",
            "protobuf",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--evidence-id",
            "evidence-current",
            "--body-codec",
            "protobuf",
            "--unordered-path",
            r#"{"field_path":[3,1,6,3],"display_path":"rule_collection.experiments.groups.white_list","element_type":"string","source_evidence":"src/rule.rs:white_list is a Set"}"#,
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "motan",
            "--evidence-id",
            "evidence-current",
            "--protocol",
            "protobuf",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "motan",
            "--evidence-id",
            "evidence-current",
            "--protocol",
            "protobuf",
            "--unordered-path",
            r#"{"field_path":[3],"display_path":"payload","element_type":"bytes","source_evidence":"src/rule.rs:payload is a Set"}"#,
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "dependency-rule",
            "plan",
            "memcached",
            "protobuf-timestamp",
            "--evidence-id",
            "evidence-current",
            "--rule-id",
            "user-info-loading-time",
            "--port",
            "15138",
            "--key-prefix",
            "u",
            "--field-number",
            "50",
            "--source-evidence",
            "CacheService.java:2044 sets loading_time from Unix seconds",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "transfer",
            "fnv1a64:binding",
            "--agent-handle",
            "replacement-agent-43",
            "--reason",
            "stored handle is unavailable after session replacement",
            "--approve-ownership-transfer",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "transfer",
            "fnv1a64:binding",
            "--agent-handle",
            "replacement-agent-43",
            "--reason",
            "stored handle is unavailable after session replacement",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "init",
            "--source-container",
            "friendship",
            "--recording-port",
            "18181",
        ])
        .is_err()
    );
    for native_port_flag in ["--source-http-port", "--target-port"] {
        assert!(
            Cli::try_parse_from([
                "test",
                "init",
                "--source-container",
                "friendship",
                native_port_flag,
                "8081",
            ])
            .is_err()
        );
    }
    let RewriteCommand::Init(default_init) =
        Cli::try_parse_from(["test", "init", "--source-container", "friendship"])
            .unwrap()
            .command
    else {
        panic!("expected init command");
    };
    assert_eq!(
        default_init.http_gateway_port,
        traffic_e2e::DEFAULT_HTTP_GATEWAY_PORT
    );
    assert!(default_init.command.is_none());
    let RewriteCommand::Init(preflight) =
        Cli::try_parse_from(["test", "init", "preflight", "--duration-seconds", "30"])
            .unwrap()
            .command
    else {
        panic!("expected init command");
    };
    assert!(matches!(
        preflight.command,
        Some(project_init::ProjectInitCommand::Preflight(_))
    ));
    assert!(Cli::try_parse_from(["test", "init", "preflight", "--duration-seconds", "0"]).is_err());
    assert!(Cli::try_parse_from(["test", "init", "preflight", "--api", "GET /business"]).is_err());
    assert!(
        Cli::try_parse_from([
            "test",
            "init",
            "--source-container",
            "friendship",
            "--breeze=custom-breeze",
            "--http-gateway-port",
            "18181",
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["test", "init", "--source-container", "friendship"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "init",
            "--source-container",
            "friendship",
            "--env-file",
            "/tmp/target.env",
        ])
        .is_ok()
    );
    for removed in [
        "--startup-mount",
        "--startup-env",
        "--target-port-env",
        "--replay-ca-env",
    ] {
        assert!(
            Cli::try_parse_from([
                "test",
                "init",
                "--source-container",
                "friendship",
                removed,
                "VALUE",
            ])
            .is_err()
        );
    }
    assert!(Cli::try_parse_from(["test", "startup", "env", "list"]).is_ok());
    assert!(Cli::try_parse_from(["test", "startup", "env", "equals", "DATABASE_URL"]).is_ok());
    assert!(
        Cli::try_parse_from(["test", "startup", "mount", "ensure", "/data1/authconfs",]).is_ok()
    );
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
            "recorder-capture",
            "plan",
            "--evidence-id",
            "evidence-1",
            "--endpoint",
            "counter.example.com:9332",
            "--source-evidence",
            "CounterService.java:88 reads the counter backend",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "recorder-capture",
            "apply",
            "recorder-capture-plan-0123456789abcdef",
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
            "target-quality",
            "run",
            "target-quality-fnv1a64-0123456789abcdef",
            "--api",
            "GET /api/widgets/*",
            "--hardcode-ai-verified",
            "src/client.rs:42:18=legacy@abcdef1:src/main/java/Client.java:96:27",
            "--hardcode-ai-verified",
            "src/other.rs:7:9=legacy@abcdef1:src/main/java/Other.java:31:12",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "--target-root",
            "/canonical/target",
            "evidence",
            "evq-r1-issue-representatives",
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(["test", "status", "--api", "GET /api/widgets/*"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "verification",
            "request",
            "--api",
            "GET /api/widgets/*",
            "--api",
            "POST /api/widgets",
            "--reason",
            "shared response mapper changed",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "verification",
            "request",
            "--reason",
            "shared response mapper changed",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "case",
            "dependencies",
            "/repo/.traffic-e2e/local/artifacts/run/api/case-a",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "case",
            "dependencies",
            "/repo/.traffic-e2e/local/artifacts/run/api/case-a",
            "dependency-target-0123456789abcdef",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "route",
            "--cause",
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
            "--cause",
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
    assert!(
        Cli::try_parse_from([
            "test",
            "route",
            "--cause",
            "missing-recorded-resource",
            "--evidence-id",
            "evidence-1",
            "--source-ref",
            "src/client.rs:42",
            "--endpoint",
            "cache.example.com",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "route",
            "--cause",
            "missing-recorded-resource",
            "--evidence-id",
            "evidence-1",
            "--source-ref",
            "src/client.rs:42",
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["test", "repair", "verify", "repair-1"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "confirm",
            "fnv1a64:dispatch",
            "--agent-handle",
            "runtime-agent-42",
            "--agent-name",
            "friends-ids-worker",
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
            "get",
            "--evidence-id",
            "evidence-1",
            "--ownership",
            "process-owned",
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
            "get",
            "--evidence-id",
            "evidence-1",
            "--ownership",
            "process-owned",
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
    let memcached = Cli::try_parse_from([
        "test",
        "dependency-rule",
        "plan",
        "memcached",
        "get",
        "--help",
    ])
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

#[test]
fn memcached_protobuf_timestamp_help_is_rule_specific() {
    let help = Cli::try_parse_from([
        "test",
        "dependency-rule",
        "plan",
        "memcached",
        "protobuf-timestamp",
        "--help",
    ])
    .unwrap_err()
    .to_string();

    assert!(help.contains("protobuf Unix timestamp"));
    assert!(help.contains("--rule-id <RULE_ID>"));
    assert!(help.contains("--port <PORT>"));
    assert!(help.contains("--field-number <FIELD_NUMBER>"));
    assert!(help.contains("--source-evidence <SOURCE_EVIDENCE>"));
    assert!(!help.contains("--namespace"));
    assert!(!help.contains("--group"));
    assert!(!help.contains("--tolerance"));
    assert!(!help.contains("--offset"));
}
