//! Durable shared policy intents cannot be bypassed by another verification.
use super::*;

fn interrupted(fixture: &Fixture) -> (String, Vec<u8>) {
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let original = fs::read(fixture.policy()).unwrap();
    let collision = crate::internal_runtime::root(fixture.root())
        .join("rewrite")
        .join(format!(
            ".state.json.tmp.{}.{}",
            std::process::id(),
            fixture.state().revision + 1
        ));
    fs::write(
        &collision,
        "final state publication fails after durable intent",
    )
    .unwrap();
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
    fs::remove_file(collision).unwrap();
    let journal = fixture.state();
    let record = journal
        .rule_plan
        .as_ref()
        .unwrap()
        .unified
        .as_ref()
        .unwrap();
    assert!(record.applying());
    // Simulate termination after the exact authorized policy publication.
    fs::write(fixture.policy(), &record.updated).unwrap();
    (plan.plan_id, original)
}

#[tokio::test]
async fn public_next_cannot_verify_a_partially_published_shared_policy() {
    use crate::rewrite::{replay_admission, worker::runtime};
    let fixture = Fixture::new();
    let (_, _) = interrupted(&fixture);
    let journal = fixture.state();
    let scope = RewriteWorkScope::Api { api: "/api".into() };
    let mut baseline = journal.clone();
    baseline.rule_plan = None;
    assert!(replay_admission::admitted(&baseline, &scope));
    assert!(!replay_admission::admitted(&journal, &scope));
    assert!(!runtime::acceptance_ready(&journal, &scope));
    // The policy is shared: a parked API's handoff cannot evade the owner intent.
    let mut sibling = journal.active_slice.clone();
    sibling.api = "POST /other".into();
    sibling.rule_plan = None;
    sibling.rule_replay_pending = true;
    let mut concurrent = journal.clone();
    concurrent
        .parked_slices
        .insert(sibling.api.clone(), sibling);
    assert!(!replay_admission::admitted(
        &concurrent,
        &RewriteWorkScope::Api {
            api: "/other".into()
        }
    ));
    let attempts = journal.attempts.len();
    let action = crate::rewrite::next_rewrite(crate::rewrite::RewriteNextOptions {
        target_root: fixture.root().into(),
        api: Some("/api".parse().unwrap()),
        source_route: None,
    })
    .await
    .unwrap();
    assert!(!action.terminal_allowed);
    assert!(!matches!(
        action.action,
        crate::rewrite::RewriteAction::Complete { .. }
    ));
    let retained = fixture.state();
    assert_eq!(retained.attempts.len(), attempts);
    assert!(retained.rule_plan.is_some() && !retained.e2e_current);
    assert!(matches!(
        crate::rewrite::traffic_operation::state(fixture.root()).unwrap(),
        crate::rewrite::traffic_operation::TrafficOperationState::Absent
    ));
}

#[test]
fn recovery_rolls_back_exact_published_bytes_and_never_drops_a_foreign_write_intent() {
    for foreign in [false, true] {
        let fixture = Fixture::new();
        let (plan, original) = interrupted(&fixture);
        if foreign {
            fs::write(
                fixture.policy(),
                format!(
                    "{}# concurrent policy write\n",
                    fs::read_to_string(fixture.policy()).unwrap()
                ),
            )
            .unwrap();
        } else {
            // Make frozen evidence stale; the applied effect must be reverted
            // before the stale intent can be retired.
            let actual = fixture.paths.replay.parent().unwrap().join("case-1.json");
            fs::write(actual, "{}").unwrap();
        }
        let result = recover_rewrite_rule_plan(fixture.context(), &plan);
        if foreign {
            assert!(result.is_err());
            assert!(fixture.state().rule_plan.is_some());
            assert!(
                fs::read_to_string(fixture.policy())
                    .unwrap()
                    .contains("concurrent policy write")
            );
        } else {
            let report = result.unwrap();
            assert_eq!(report["applied"], false);
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
            assert!(fixture.state().rule_plan.is_none() && fixture.state().rule_replay_pending);
        }
    }
}
