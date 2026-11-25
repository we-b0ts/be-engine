use super::*;
use std::fs;

fn fixture(root: &Path) -> (RunLayout, ActiveRunState, PathBuf) {
    let (mut layout, _, state) = crate::test_session::session(root);
    layout.active_dir = root.join("runtime/.active");
    fs::write(
        layout
            .case_source
            .join(crate::dependency::observation::MANIFEST_FILE),
        "{}",
    )
    .unwrap();
    let directory = layout
        .run_root
        .join("focused")
        .join(crate::support::api_directory("GET /api"))
        .join("latest");
    fs::create_dir_all(directory.join("reports")).unwrap();
    let mut state = crate::focused_batch::project(&state, "GET /api");
    state.replay_report = directory.join("reports/replay-report.json");
    fs::write(&state.replay_report, "{}").unwrap();
    store::write_yaml(&directory.join("state.yaml"), &state).unwrap();
    (layout, state, directory)
}

#[test]
fn focused_diagnostic_binds_session_attempt_scope_and_inactive_publication() {
    let temp = tempfile::tempdir().unwrap();
    let (layout, mut state, directory) = fixture(temp.path());
    let (_, report) = focused_report(&layout, "session", "GET /api", 1).unwrap();
    assert_eq!(report.session_id, "session");
    assert_eq!(report.sequence, 1);
    assert_eq!(report.key_context, layout.case_source);
    assert_eq!(report.path, state.replay_report);
    assert!(focused_report(&layout, "another-session", "GET /api", 1).is_err());
    assert!(focused_report(&layout, "session", "GET /api", 2).is_err());
    assert!(focused_report(&layout, "session", "POST /other", 1).is_err());
    state.cases[0].group_id = "POST /other".into();
    store::write_yaml(&directory.join("state.yaml"), &state).unwrap();
    assert!(focused_report(&layout, "session", "GET /api", 1).is_err());
    let active = directory.parent().unwrap().join(".active");
    fs::create_dir(&active).unwrap();
    assert!(
        focused_report(&layout, "session", "GET /api", 1)
            .unwrap_err()
            .to_string()
            .contains("while its attempt is active")
    );
}

#[test]
fn diagnostics_reject_unfinalized_foreign_source_and_escaped_reports() {
    let temp = tempfile::tempdir().unwrap();
    let (layout, original, directory) = fixture(temp.path());
    for invalid in 0..4 {
        let mut state = original.clone();
        match invalid {
            0 => state.status = RunStatus::Running,
            1 => state.replay_finalized = false,
            2 => state.case_source = temp.path().join("foreign-recording"),
            _ => state.replay_report = temp.path().join("foreign-report.json"),
        }
        store::write_yaml(&directory.join("state.yaml"), &state).unwrap();
        assert!(published(&layout, &directory, Some("session")).is_err());
    }
    for invalid in ["", "../session", "session/path", "session\n"] {
        assert!(session_report(&layout, invalid, Some(("GET /api", 1))).is_err());
    }
}

#[test]
fn malformed_existing_archive_never_falls_back_to_current_focused_session() {
    let temp = tempfile::tempdir().unwrap();
    let (layout, _, _) = fixture(temp.path());
    let archive = layout.run_root.join("actual-batches/session");
    fs::create_dir_all(&archive).unwrap();
    fs::write(archive.join("state.yaml"), "not a published run state").unwrap();
    assert!(session_report(&layout, "session", Some(("GET /api", 1))).is_err());
    assert!(focused_report(&layout, "session", "GET /api", 1).is_ok());
}
