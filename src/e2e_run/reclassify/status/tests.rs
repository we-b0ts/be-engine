use super::*;
use crate::e2e_run::{reclassify, test_session};

#[test]
fn interrupted_startup_without_a_session_does_not_block_status_or_authorize_revision() {
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    let path = test_session::state_path(&context, "GET /api");
    let mut primary: ActiveRunState = store::read_yaml(&path).unwrap();
    primary.status = RunStatus::Interrupted;
    primary.session_id = None;
    primary.replay_finalized = false;
    primary.aggregate_complete = false;
    primary.aggregate_clean = false;
    primary.errors = vec!["failed to start Replay: executable unavailable".into()];
    store::write_yaml(&path, &primary).unwrap();
    fs::remove_file(&primary.replay_report).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(
        !with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context.clone(), "GET /api")
        })
        .unwrap()
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(
        reclassify::ensure_focused_background_reclassification_revisable(
            context.clone(),
            "GET /api"
        )
        .is_err()
    );
    primary.replay_finalized = true;
    store::write_yaml(&path, &primary).unwrap();
    assert!(focused_background_reclassification_pending(context, "GET /api").is_err());
}

#[test]
fn status_detects_legacy_split_without_opening_recording_cases() {
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    test_session::classify_stream(target.path());
    let (report, progress) = test_session::legacy_split(&context);
    let report_before = fs::read(&report).unwrap();
    let progress_before = fs::read(&progress).unwrap();
    // Status uses prepared membership; execution must still reject unavailable evidence.
    fs::remove_file(context.case_source.join("get-case/request.json")).unwrap();
    assert!(
        with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context.clone(), "OPTIONS /api")
        })
        .unwrap()
    );
    assert_eq!(fs::read(&report).unwrap(), report_before);
    assert_eq!(fs::read(&progress).unwrap(), progress_before);
    assert!(
        reclassify::ensure_focused_background_reclassification_revisable(context, "GET /api")
            .is_err()
    );
}

#[test]
fn methods_and_nested_projections_share_one_query_but_next_query_observes_changes() {
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    test_session::classify_stream(target.path());
    test_session::legacy_split(&context);
    let path = test_session::state_path(&context, "GET /api");
    let primary: ActiveRunState = store::read_yaml(&path).unwrap();
    let sibling: ActiveRunState =
        store::read_yaml(&test_session::state_path(&context, "OPTIONS /api")).unwrap();
    with_background_reclassification_snapshot(|| {
        assert!(focused_background_reclassification_pending(context.clone(), "GET /api").unwrap());
        // A newly published report is visible on the next query, not halfway through this one.
        fs::copy(&sibling.replay_report, &primary.replay_report).unwrap();
        with_background_reclassification_snapshot(|| {
            assert!(
                focused_background_reclassification_pending(context.clone(), "OPTIONS /api")
                    .unwrap()
            );
        });
        assert!(focused_background_reclassification_pending(context.clone(), "GET /api").unwrap());
    });
    assert!(
        !with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context, "GET /api")
        })
        .unwrap()
    );
}

#[test]
fn next_query_observes_changed_rules_and_rejects_changed_session_membership() {
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    test_session::classify_stream(target.path());
    test_session::legacy_split(&context);
    assert!(
        with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context.clone(), "GET /api")
        })
        .unwrap()
    );
    let policy = target.path().join(".traffic-e2e/policy.yaml");
    let document = fs::read_to_string(&policy)
        .unwrap()
        .replace("id: stream-startup", "id: stream-startup-v2");
    fs::write(&policy, document).unwrap();
    assert!(
        !with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context.clone(), "GET /api")
        })
        .unwrap()
    );
    let path = test_session::state_path(&context, "OPTIONS /api");
    let mut sibling: ActiveRunState = store::read_yaml(&path).unwrap();
    sibling.cases.clear();
    store::write_yaml(&path, &sibling).unwrap();
    assert!(
        with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context, "GET /api")
        })
        .is_err()
    );
}

#[test]
fn checkpoint_detection_does_not_require_reports_and_active_attempts_take_precedence() {
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    let (_, layout) = config::resolve_layout(target.path(), &context.case_source, None).unwrap();
    let inventory =
        crate::case_group::load_case_group_inventory(&layout.group_index_path, &layout.case_source)
            .unwrap();
    let members = session::members(&layout, &inventory, "GET /api").unwrap();
    let index = store::load_or_create_index(&layout, &layout.run_key, &layout.case_source).unwrap();
    let revision = session::preflight(&layout, &members, &index).unwrap();
    session::begin(&layout, &revision).unwrap();
    for member in members {
        fs::remove_file(member.state.replay_report).unwrap();
    }
    assert!(
        with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context.clone(), "OPTIONS /api")
        })
        .unwrap()
    );
    let path = test_session::state_path(&context, "GET /api");
    fs::create_dir(path.parent().unwrap().parent().unwrap().join(".active")).unwrap();
    assert!(
        !with_background_reclassification_snapshot(|| {
            focused_background_reclassification_pending(context, "GET /api")
        })
        .unwrap()
    );
}
