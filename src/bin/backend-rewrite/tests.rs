use super::*;
use clap::CommandFactory;

#[test]
fn source_exchange_selectors_require_a_target_and_both_reference_parts() {
    let prefix = ["test", "case", "dependencies", "/case"];
    let connection = "123e4567-e89b-42d3-a456-426614174000";
    for tail in [
        vec!["--connection-id", connection],
        vec!["target", "--sequence", "0"],
        vec!["--connection-id", connection, "--sequence", "0"],
    ] {
        assert!(Cli::try_parse_from(prefix.into_iter().chain(tail)).is_err());
    }
    assert!(
        Cli::try_parse_from(prefix.into_iter().chain([
            "target",
            "--connection-id",
            connection,
            "--sequence",
            "0"
        ]))
        .is_ok()
    );
}

#[test]
fn http_coordinator_commands_accept_routes_and_reject_method_selectors() {
    let prefixes = [
        vec!["test", "next", "--api"],
        vec!["test", "status", "--api"],
        vec!["test", "evidence", "--api"],
        vec![
            "test",
            "verification",
            "request",
            "--reason",
            "shared change",
            "--api",
        ],
        vec![
            "test",
            "worker",
            "confirm",
            "--agent-handle",
            "worker",
            "--api",
        ],
        vec!["test", "review", "check", "--worktree", "/worker", "--api"],
    ];
    for prefix in prefixes {
        let mut args = prefix.clone();
        args.push("/api/subscriptions/*");
        assert!(
            Cli::try_parse_from(args).is_ok(),
            "route should be accepted: {prefix:?}"
        );
        for method in [
            "GET /api/subscriptions/*",
            "PUT /api/subscriptions/*",
            "GET|PUT /api/subscriptions/*",
        ] {
            let mut args = prefix.clone();
            args.push(method);
            assert!(
                Cli::try_parse_from(args).is_err(),
                "method selector should be rejected: {prefix:?}"
            );
        }
    }
}

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
            "wait",
            "inventory",
            "purpose",
            "case",
            "repository-analysis",
            "dependency-attribution",
            "implementer",
            "evidence",
            "rule",
            "recorder-capture",
            "route",
            "repair",
            "worker",
            "expert",
            "review",
            "operation",
            "verification",
            "target-quality",
            "recover",
        ]
    );
}

#[test]
fn parses_worker_feedback_and_explicit_operation_retry() {
    for activity in [
        "running",
        "queued",
        "idle",
        "handoff_ready",
        "integrated",
        "rework_required",
    ] {
        assert!(
            Cli::try_parse_from([
                "test",
                "worker",
                "report",
                "--agent-handle",
                "runtime-handle",
                "--activity",
                activity,
                "--handoff-id",
                "commit-id",
            ])
            .is_ok()
        );
    }
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "report",
            "--agent-handle",
            "runtime-handle",
            "--activity",
            "finished",
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["test", "operation", "retry", "operation-id"]).is_ok());
}

#[test]
fn worker_identity_requires_handles_and_rejects_old_id_arguments() {
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "confirm",
            "--api",
            "/api",
            "--agent-handle",
            "runtime-worker"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "confirm",
            "--agent-handle",
            "runtime-worker"
        ])
        .is_err()
    );
    for argv in [
        vec![
            "test",
            "worker",
            "confirm",
            "old-dispatch",
            "--agent-handle",
            "runtime-worker",
        ],
        vec![
            "test",
            "worker",
            "report",
            "old-dispatch",
            "--agent-handle",
            "runtime-worker",
            "--activity",
            "running",
        ],
        vec![
            "test",
            "worker",
            "transfer",
            "old-binding",
            "--agent-handle",
            "replacement",
            "--reason",
            "missing",
            "--approve-ownership-transfer",
        ],
    ] {
        assert!(Cli::try_parse_from(argv).is_err());
    }
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
    let init = [
        "test",
        "init",
        "--source-pod",
        "friendship",
        "--namespace",
        "wb-plat-ide",
    ];
    assert!(Cli::try_parse_from(init).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "case-pattern",
            "apply",
            "case-patterns-current",
            "--patterns-json",
            r#"["/api/tasks/*/tree"]"#,
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "init",
            "--source-pod",
            "friendship",
            "--namespace",
            "wb-plat-ide",
            "--breeze",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "startup",
            "env",
            "ensure",
            "DATABASE_URL",
            "--from-source",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "startup",
            "env",
            "ensure",
            "DATABASE_URL",
            "--from-source",
            "--value",
            "one",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "rule",
            "plan",
            "--file",
            "rules.yaml",
            "--evidence",
            "current"
        ])
        .is_ok()
    );
    for retired in ["dependency-rule", "jwt-rule"] {
        assert!(Cli::try_parse_from(["test", retired, "plan"]).is_err());
    }
    assert!(
        Cli::try_parse_from([
            "test",
            "worker",
            "transfer",
            "--previous-agent-handle",
            "runtime-agent-42",
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
            "--previous-agent-handle",
            "runtime-agent-42",
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
            "--source-pod",
            "friendship",
            "--namespace",
            "wb-plat-ide",
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
                "--source-pod",
                "friendship",
                "--namespace",
                "wb-plat-ide",
                native_port_flag,
                "8081",
            ])
            .is_err()
        );
    }
    let RewriteCommand::Init(default_init) = Cli::try_parse_from(init).unwrap().command else {
        panic!("expected init command");
    };
    assert_eq!(
        default_init.http_gateway_port,
        traffic_e2e::DEFAULT_HTTP_GATEWAY_PORT
    );
    assert_eq!(
        default_init.http_backend_port,
        traffic_e2e::DEFAULT_HTTP_BACKEND_PORT
    );
    assert!(Cli::try_parse_from(["test", "init", "preflight"]).is_err());
    assert!(Cli::try_parse_from(["test", "init", "preflight", "--duration-seconds", "0"]).is_err());
    assert!(Cli::try_parse_from(["test", "init", "preflight", "--api", "/business"]).is_err());
    assert!(
        Cli::try_parse_from([
            "test",
            "init",
            "--source-pod",
            "friendship",
            "--namespace",
            "wb-plat-ide",
            "--http-backend-port",
            "8081",
            "--http-gateway-port",
            "18181",
        ])
        .is_ok()
    );
    assert!(Cli::try_parse_from(init).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "init",
            "--source-pod",
            "friendship",
            "--namespace",
            "wb-plat-ide",
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
        "--readiness-status",
    ] {
        assert!(
            Cli::try_parse_from([
                "test",
                "init",
                "--source-pod",
                "friendship",
                "--namespace",
                "wb-plat-ide",
                removed,
                "VALUE",
            ])
            .is_err()
        );
    }
    assert!(Cli::try_parse_from(["test", "startup", "env", "list"]).is_ok());
    assert!(Cli::try_parse_from(["test", "startup", "env", "equals", "DATABASE_URL"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "startup",
            "env",
            "ensure",
            "DATABASE_URL",
            "--value",
            "mysql://source-compatible",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "startup",
            "env",
            "ensure",
            "DATABASE_URL",
            "--value",
            "one",
            "--from-env",
            "SOURCE_DATABASE_URL",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["test", "startup", "mount", "ensure", "/data1/authconfs",]).is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "test",
            "next",
            "--api",
            "/api/users/*",
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
            "/api/widgets/*",
        ])
        .is_err()
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
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["test", "recording", "execute", "recording-0123456789abcdef",])
            .is_err()
    );
    assert!(Cli::try_parse_from(["test", "evidence", "evq-r1-issue-representatives"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "target-quality",
            "run",
            "target-quality-fnv1a64-0123456789abcdef",
            "--api",
            "/api/widgets/*",
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
    assert!(Cli::try_parse_from(["test", "status", "--api", "/api/widgets/*"]).is_ok());
    assert!(
        Cli::try_parse_from([
            "test",
            "verification",
            "request",
            "--api",
            "/api/widgets/*",
            "--api",
            "/api/widgets",
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
            "--api",
            "/api",
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
        .is_err()
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
    assert!(Cli::try_parse_from(["test", "rule", "plan", "--evidence", "current"]).is_err());
}

#[test]
fn rule_help_exposes_one_document_and_actual_evidence_for_every_domain() {
    let help = Cli::try_parse_from(["test", "rule", "plan", "--help"])
        .unwrap_err()
        .to_string();
    for required in ["--file", "--evidence", "traffic-policy/v3"] {
        assert!(help.contains(required), "{help}");
    }
    for retired in [
        "--kind",
        "--body-codec",
        "--json-pointer",
        "--dynamic-value",
        "--mysql-time",
    ] {
        assert!(!help.contains(retired), "{help}");
    }
}
