use super::*;
use clap::CommandFactory;

#[test]
fn exposes_the_flat_source_commands() {
    let command = Cli::command();
    command.clone().debug_assert();
    assert_eq!(command.get_name(), "be-replay");
    assert_eq!(command.get_version(), Some(traffic_e2e::BINARY_VERSION));
    let names = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "init",
            "startup",
            "run",
            "status",
            "events",
            "dependency",
            "target",
            "plan"
        ]
    );
    for old in [
        "session",
        "next",
        "wait",
        "inventory",
        "regression",
        "purpose",
        "case",
        "repository-analysis",
        "dependency-attribution",
        "implementer",
        "evidence",
        "evidence-detail",
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
    ] {
        let error = Cli::try_parse_from(["test", old, "--help"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{old}"
        );
    }
}

#[test]
fn source_command_options_bind_the_selected_recording_and_attempt() {
    let recording = "20261125131020";
    let attempt = uuid::Uuid::from_u128(1);
    let attempt_id = attempt.to_string();
    let cli = Cli::try_parse_from([
        "test",
        "--recording-run-id",
        recording,
        "status",
        "--run-key",
        "target-main",
        "--attempt-id",
        &attempt_id,
    ])
    .unwrap();
    assert_eq!(cli.recording_run_id.as_deref(), Some(recording));
    assert!(matches!(
        cli.command,
        RewriteCommand::Source(event_session::SourceCommand::Status { run_key, attempt_id })
            if run_key.as_deref() == Some("target-main") && attempt_id == Some(attempt)
    ));
    let cli = Cli::try_parse_from([
        "test",
        "run",
        "--recording-run-id",
        recording,
        "--run-key",
        "target-main",
    ])
    .unwrap();
    assert_eq!(cli.recording_run_id.as_deref(), Some(recording));
    assert!(matches!(
        cli.command,
        RewriteCommand::Source(event_session::SourceCommand::Run { run_key })
            if run_key.as_deref() == Some("target-main")
    ));
    assert!(Cli::try_parse_from(["test", "status", "--attempt-id", "not-a-uuid"]).is_err());
    assert!(Cli::try_parse_from(["test", "status", "--api", "/api"]).is_err());
    assert!(Cli::try_parse_from(["test", "startup", "env", "list"]).is_ok());
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
