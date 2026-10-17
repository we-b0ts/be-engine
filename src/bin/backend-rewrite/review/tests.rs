use super::super::*;

#[test]
fn exposes_worker_and_integrated_review_commands() {
    for args in [
        vec![
            "test",
            "review",
            "batch",
            "--worktree",
            "/integration",
            "--api",
            "/a",
            "--api",
            "/b",
        ],
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
            "/api",
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
            "/api",
            "--handoff-id",
            "commit",
        ],
        vec![
            "test",
            "review",
            "check",
            "--integration",
            "--worktree",
            "/integration",
            "--batch-handoffs",
            "/integration/handoffs.json",
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
            "api:/api",
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
            "api:/api",
        ],
        vec![
            "test",
            "worker",
            "confirm",
            "--api",
            "/api",
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
}

#[test]
fn review_requires_a_delivery_worktree_and_worker_scope() {
    for args in [
        vec!["test", "review", "batch", "--worktree", "/integration"],
        vec!["test", "review", "batch", "--api", "/api"],
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
            "/api",
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
    for identity in [vec!["--api", "/api"], vec!["--handoff-id", "commit"]] {
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

#[test]
fn final_review_selects_global_integration_without_a_separate_integration_flag() {
    let cli = Cli::try_parse_from([
        "test",
        "review",
        "check",
        "--pre-revalidation",
        "--worktree",
        "/integration",
    ])
    .unwrap();
    let RewriteCommand::Review(args) = cli.command else {
        panic!("expected review command");
    };
    let super::ReviewCommand::Check {
        pre_revalidation,
        integration,
        api,
        handoff_id,
        batch_handoffs,
        ..
    } = args.command
    else {
        panic!("expected check command");
    };
    assert!(pre_revalidation);
    assert!(!integration);
    assert!(api.is_none());
    assert!(handoff_id.is_none());
    assert!(batch_handoffs.is_none());
}

#[test]
fn final_review_rejects_scoped_or_batch_delivery_selectors() {
    for forbidden in [
        vec!["--api", "/api"],
        vec!["--handoff-id", "commit"],
        vec!["--batch-handoffs", "/integration/batch.json"],
    ] {
        let mut argv = vec![
            "test",
            "review",
            "check",
            "--pre-revalidation",
            "--integration",
            "--worktree",
            "/integration",
        ];
        argv.extend(forbidden);
        assert!(Cli::try_parse_from(&argv).is_err(), "accepted {argv:?}");
    }
    assert!(Cli::try_parse_from(["test", "review", "check", "--pre-revalidation"]).is_err());
}
