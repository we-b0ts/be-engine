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
            "switch-recording-id",
            "status",
            "apis",
            "events",
            "dependency",
            "target",
            "plan",
            "report"
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
        RewriteCommand::Source(event_session::SourceCommand::Status { run_key, attempt_id, with_assignments: false })
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
        RewriteCommand::Source(event_session::SourceCommand::Run { run_key, user_confirm: false })
            if run_key.as_deref() == Some("target-main")
    ));
    assert!(Cli::try_parse_from(["test", "status", "--attempt-id", "not-a-uuid"]).is_err());
    assert!(Cli::try_parse_from(["test", "status", "--api", "/api"]).is_err());
    assert!(Cli::try_parse_from(["test", "startup", "env", "list"]).is_ok());
}

#[test]
fn target_evidence_requires_one_report_selector() {
    let attempt = uuid::Uuid::from_u128(1);
    let observation = uuid::Uuid::from_u128(2);
    let attempt_id = attempt.simple().to_string();
    let observation_id = observation.to_string();
    let command =
        Cli::try_parse_from(["test", "target", "--attempt", &attempt_id, &observation_id])
            .unwrap()
            .command;
    assert!(matches!(
        command,
        RewriteCommand::Source(event_session::SourceCommand::Target {
            attempt: Some(id), report: None, observation_id,
        }) if id == attempt && observation_id == observation
    ));
    assert!(
        Cli::try_parse_from([
            "test",
            "target",
            "--report",
            "evidence.json",
            &observation_id
        ])
        .is_ok()
    );
    for selection in [
        vec![],
        vec!["--attempt", "invalid"],
        vec!["--attempt", &attempt_id, "--report", "evidence.json"],
    ] {
        let args = ["test", "target"]
            .into_iter()
            .chain(selection)
            .chain([observation_id.as_str()]);
        assert!(Cli::try_parse_from(args).is_err());
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
