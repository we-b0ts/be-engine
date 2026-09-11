use super::super::*;

#[test]
fn exposes_worker_and_integrated_review_commands() {
    for args in [
        vec![
            "test",
            "review",
            "check",
            "--integration",
            "--worktree",
            "/integration",
        ],
        vec![
            "test",
            "review",
            "check",
            "--worktree",
            "/worker",
            "--api",
            "GET /api",
            "--evidence",
            "/tmp/evidence.json",
            "--hardcode-ai-verified",
            "src/client.rs:3:4=source@abcdef1:src/client.go:5:6",
            "--hardcode-ai-verified",
            "src/client.rs:8:9=source@abcdef1:src/client.go:10:11",
        ],
        vec![
            "test",
            "review",
            "check",
            "--integration",
            "--worktree",
            "/integration",
            "--api",
            "GET /api",
            "--handoff-id",
            "commit",
        ],
        vec![
            "test",
            "review",
            "accept",
            "--report",
            "/integration/report.json",
        ],
        vec![
            "test",
            "review",
            "check",
            "--worktree",
            "/worker",
            "--process-output",
            "profile",
        ],
        vec![
            "test",
            "worker",
            "report",
            "--agent-handle",
            "worker",
            "--activity",
            "integrated",
            "--handoff-id",
            "commit",
            "--review-report",
            "/integration/report.json",
        ],
        vec!["test", "review", "show"],
        vec![
            "test",
            "review",
            "rework",
            "--finding",
            "finding-1",
            "--owner",
            "api:GET /api",
        ],
        vec![
            "test",
            "review",
            "rework",
            "--report",
            "/integration/failed-report.json",
            "--finding",
            "finding-1",
            "--owner",
            "api:GET /api",
        ],
        vec![
            "test",
            "worker",
            "confirm",
            "--api",
            "GET /api",
            "--agent-handle",
            "worker",
            "--worktree",
            "/worker",
        ],
        vec![
            "test",
            "worker",
            "report",
            "--agent-handle",
            "worker",
            "--activity",
            "handoff_ready",
            "--handoff-id",
            "commit",
            "--review-report",
            "/worker/report.json",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    assert!(
        Cli::try_parse_from([
            "test",
            "review",
            "check",
            "--worktree",
            "/worker",
            "--api",
            "GET /api",
            "--process-output",
            "profile"
        ])
        .is_err()
    );
}

#[test]
fn review_requires_a_delivery_worktree_and_worker_scope() {
    for args in [
        vec!["test", "review", "check"],
        vec!["test", "review", "check", "--integration"],
        vec!["test", "review", "check", "--worktree", "/worker"],
        vec![
            "test",
            "review",
            "check",
            "--worktree",
            "/worker",
            "--api",
            "GET /api",
            "--handoff-id",
            "commit",
        ],
        vec!["test", "review", "accept"],
    ] {
        assert!(Cli::try_parse_from(&args).is_err(), "accepted {args:?}");
    }
}

#[test]
fn integration_review_rejects_incomplete_handoff_identity_before_accessing_state() {
    for identity in [
        vec!["--api", "GET /api"],
        vec!["--process-output", "profile"],
        vec!["--handoff-id", "commit"],
    ] {
        let mut argv = vec![
            "test",
            "review",
            "check",
            "--integration",
            "--worktree",
            "/integration",
        ];
        argv.extend(identity);
        let cli = Cli::try_parse_from(argv).unwrap();
        let RewriteCommand::Review(args) = cli.command else {
            panic!("expected review command");
        };
        let error = review::run(PathBuf::from("/uninitialized-target"), args, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("both a work-item selector and --handoff-id")
        );
    }
}
