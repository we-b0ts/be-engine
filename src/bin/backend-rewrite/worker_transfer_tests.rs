use super::*;

#[test]
fn worker_transfer_accepts_user_approval_or_a_complete_runtime_query() {
    let base = [
        "test",
        "worker",
        "transfer",
        "--previous-agent-handle",
        "old-worker",
        "--agent-handle",
        "new-worker",
        "--reason",
        "original owner missing",
    ];
    assert!(Cli::try_parse_from(base).is_err());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--approve-ownership-transfer"])).is_ok());
    for command in ["ListAgents", "/list-agents", "runtime.get_agent"] {
        let cli = Cli::try_parse_from(base.into_iter().chain([
            "--runtime-query-command",
            command,
            "--runtime-query-at",
            "2026-09-12T12:00:00+08:00",
        ]))
        .unwrap();
        let RewriteCommand::Worker(WorkerArgs {
            command: WorkerCommand::Transfer(args),
        }) = cli.command
        else {
            panic!("expected worker transfer");
        };
        assert!(!args.approve_ownership_transfer);
        assert_eq!(args.runtime_query_command.as_deref(), Some(command));
        assert_eq!(
            args.runtime_query_at.as_deref(),
            Some("2026-09-12T12:00:00+08:00")
        );
    }
    for extra in [
        vec!["--runtime-query-command", "ListAgents"],
        vec!["--runtime-query-at", "2026-09-12T04:00:00Z"],
        vec![
            "--approve-ownership-transfer",
            "--runtime-query-command",
            "ListAgents",
        ],
        vec![
            "--approve-ownership-transfer",
            "--runtime-query-at",
            "2026-09-12T04:00:00Z",
        ],
        vec![
            "--approve-ownership-transfer",
            "--runtime-query-command",
            "ListAgents",
            "--runtime-query-at",
            "2026-09-12T04:00:00Z",
        ],
    ] {
        assert!(Cli::try_parse_from(base.into_iter().chain(extra)).is_err());
    }
}
