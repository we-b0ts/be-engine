use std::fs;
use std::path::Path;
use std::process::Command;

use super::*;
use crate::rewrite::{self, inventory, store::RewriteStore, test_support};

const API: &str = "GET /api/attachments/task/*/all";
const LOCAL_ROUTE: &str = "/task/{task_id}/all";
const FULL_ROUTE: &str = "/api/attachments/task/{task_id}/all";

fn pending() -> RewriteState {
    let mut state = test_support::test_state();
    inventory::install(&mut state, vec![API.into(), "GET /other".into()]).unwrap();
    state
}

#[test]
fn invalid_source_routes_leave_the_entire_binding_unchanged() {
    for route in [
        LOCAL_ROUTE,
        "/api/attachments/task/42/all",
        "/api/attachments/wrong/{task_id}/all",
        "/api/attachments/task/{task_id}/all?query=1",
        "/api/attachments/task/{task_id}/all#fragment",
        "/api/attachments/task/{task_id}/all/",
        "/api//attachments/task/{task_id}/all",
        "api/attachments/task/{task_id}/all",
        "/api/attachments/task/{task_id}/all\n",
    ] {
        let mut state = pending();
        let before = serde_json::to_value(&state).unwrap();
        assert!(
            bind_options(&mut state, None, Some(route)).is_err(),
            "{route}"
        );
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
    let error = bind_options(&mut pending(), None, Some(LOCAL_ROUTE)).unwrap_err();
    assert!(error.to_string().contains(LOCAL_ROUTE));
    assert!(
        error
            .to_string()
            .contains("include all router mount prefixes")
    );
}

#[test]
fn valid_source_route_is_idempotent_and_cannot_be_rebound() {
    let mut state = pending();
    assert!(bind_options(&mut state, None, Some(FULL_ROUTE)).unwrap());
    let bound = serde_json::to_value(&state).unwrap();
    assert!(!bind_options(&mut state, None, Some(FULL_ROUTE)).unwrap());
    assert!(
        bind_options(&mut state, None, Some("/api/attachments/task/:id/all"))
            .unwrap_err()
            .to_string()
            .contains("refusing a different --source-route")
    );
    assert_eq!(serde_json::to_value(&state).unwrap(), bound);
}

#[test]
fn persisted_invalid_source_route_can_be_corrected_and_group_existing_cases() {
    let root = tempfile::tempdir().unwrap();
    let store = RewriteStore::new(root.path()).unwrap();
    let mut state = pending();
    state.source_route = LOCAL_ROUTE.into();
    state.api_inventory[0].source_route = Some(LOCAL_ROUTE.into());
    store.save(&state).unwrap();
    let before = serde_json::to_value(&state).unwrap();

    let mut state = store.load().unwrap().unwrap();
    assert!(bind_options(&mut state, Some(&API.parse().unwrap()), Some(FULL_ROUTE)).unwrap());
    store.save(&state).unwrap();
    let state = store.load().unwrap().unwrap();
    let mut expected = before;
    expected["source_route"] = FULL_ROUTE.into();
    expected["api_inventory"][0]["source_route"] = FULL_ROUTE.into();
    expected["source_route_bindings"] = serde_json::json!({API: FULL_ROUTE});
    expected["revision"] = (expected["revision"].as_u64().unwrap() + 1).into();
    assert_eq!(serde_json::to_value(&state).unwrap(), expected);

    let source = root.path().join("recording");
    let mut originals = Vec::new();
    for id in ["42", "43"] {
        let case = source.join(format!("task-{id}/case-{id}"));
        fs::create_dir_all(&case).unwrap();
        for (name, bytes) in [
            (
                "request.json",
                serde_json::to_vec(&serde_json::json!({
                    "method": "GET", "uri": format!("/api/attachments/task/{id}/all")
                }))
                .unwrap(),
            ),
            ("expected-response.json", b"{}\n".to_vec()),
        ] {
            let path = case.join(name);
            fs::write(&path, &bytes).unwrap();
            originals.push((path, bytes));
        }
    }
    let group = crate::case_group::ensure_case_group(crate::case_group::CaseGroupOptions {
        case_source: source.clone(),
        case_dir: source.join("task-42"),
        method: "GET".into(),
        source_route: state.source_route.clone(),
        pattern: Some(API.parse::<RecordingApi>().unwrap().path_pattern().into()),
        source_revision: "source-revision".into(),
        output: root.path().join("case-groups.json"),
        recorder_config: None,
    })
    .unwrap();
    assert_eq!(group.group_id, API);
    assert_eq!(group.case_ids.len(), 2);
    for (path, bytes) in originals {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn source_route_repair_cannot_change_grouped_or_verified_work() {
    for protection in [0, 1, 2, 4, 5, 7, 8] {
        let mut state = pending();
        state.source_route = LOCAL_ROUTE.into();
        state.api_inventory[0].source_route = Some(LOCAL_ROUTE.into());
        match protection {
            0 => state.group_id = Some(API.into()),
            1 => state.phase = RewritePhase::ImplementationRequired,
            2 => state.e2e_current = true,
            4 => state.api_inventory[0].attempts = 1,
            5 => state.api_inventory[0].e2e_current = true,
            7 => state.api_inventory[0].verified_target_fingerprint = Some("verified".into()),
            8 => state.attempts.push(rewrite::model::RewriteAttemptSummary {
                engine_fingerprint: None,
                attempt: 1,
                passed: false,
                gates: crate::E2eVerificationGates {
                    responses: crate::E2eResponseGate::Nonpassing,
                    replay: crate::E2eReplayGate::Complete,
                    dependencies: crate::E2eDependencyGate::Clean,
                },
                counts: crate::E2eDiagnosisCounts {
                    selected: 1,
                    executed: 1,
                    response_passed: 0,
                    response_nonpassing: 1,
                    response_incomplete: 0,
                },
            }),
            _ => unreachable!(),
        }
        let before = serde_json::to_value(&state).unwrap();
        assert!(bind_options(&mut state, None, Some(FULL_ROUTE)).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}

#[test]
fn source_route_binding_checks_scope_and_inventory_before_mutation() {
    for invalid_index in [None, Some(1), Some(99)] {
        let mut state = pending();
        state.current_api_index = invalid_index;
        let before = serde_json::to_value(&state).unwrap();
        assert!(bind_options(&mut state, None, Some(FULL_ROUTE)).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
    let mut state = pending();
    let before = serde_json::to_value(&state).unwrap();
    assert!(
        bind_options(
            &mut state,
            Some(&"GET /other".parse().unwrap()),
            Some(FULL_ROUTE)
        )
        .is_err()
    );
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
}

#[test]
fn source_route_validation_preserves_static_and_catch_all_contracts() {
    let mut state = test_support::test_state();
    inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    assert!(!bind_options(&mut state, None, Some("/api")).unwrap());
    assert!(bind_options(&mut state, None, Some("/other")).is_err());
    assert!(
        validate_source_route(
            &"GET /api/files/**".parse().unwrap(),
            "/api/files/{path:path}"
        )
        .is_ok()
    );
    assert!(
        validate_source_route(&"GET /api/files/**".parse().unwrap(), "/api/files/list").is_err()
    );
}

#[tokio::test]
async fn next_rejects_invalid_source_route_without_persisting_it() {
    let root = tempfile::tempdir().unwrap();
    test_support::install_project_config(
        root.path(),
        "master",
        test_support::managed_test_recorder(),
        None,
    );
    fs::write(
        root.path().join(".traffic-e2e/verification.yaml"),
        "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
    )
    .unwrap();
    fs::write(root.path().join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
    git(root.path(), &["init", "-q", "-b", "master"]);
    git(root.path(), &["config", "user.name", "Test"]);
    git(root.path(), &["config", "user.email", "test@example.com"]);
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "baseline"]);
    git(root.path(), &["switch", "-qc", "fixture-work"]);
    let store = RewriteStore::new(root.path()).unwrap();
    for initialized in [false, true] {
        if initialized {
            store.save(&pending()).unwrap();
        }
        let before = serde_json::to_value(store.load().unwrap()).unwrap();
        let error = rewrite::next_rewrite(rewrite::RewriteNextOptions {
            target_root: root.path().into(),
            api: Some(API.parse::<crate::RecordingApi>().unwrap().into()),
            source_route: Some(LOCAL_ROUTE.into()),
        })
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains(if initialized {
                "same segment count"
            } else {
                "route selection requires"
            }),
            "{error:#}"
        );
        assert_eq!(serde_json::to_value(store.load().unwrap()).unwrap(), before);
    }
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
