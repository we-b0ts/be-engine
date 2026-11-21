//! A confirmed system gap keeps its repair identity while other APIs are swept.
use super::*;
use crate::model::{RewriteIssueOwner, RewriteRepairAcceptanceKind, RewriteRouteRecord};

#[test]
fn final_admission_preserves_the_active_system_gap_and_revalidates_other_complete_apis() {
    for gap_status in [
        RewriteApiStatus::Active,
        RewriteApiStatus::SystemRepairRequired,
    ] {
        let target = target(true);
        let root = target.path();
        let mut before = load(root);
        let gap_api = before.api.clone();
        let repair_id = "repair-final-system-gap";
        before.api_inventory[0].status = gap_status;
        before.api_inventory[0].e2e_current = false;
        before.phase = RewritePhase::SystemRepairRequired;
        before.e2e_current = false;
        before.active_issue = Some(crate::worker::tests::issue(
            "final-system-gap",
            1,
            "checked-candidate",
        ));
        before.active_issue.as_mut().unwrap().owner = RewriteIssueOwner::TrafficE2eSystem;
        // repair::route changes the slice phase; a selected inventory entry can
        // still be Active until selection parks that exact repair slice.
        before.route = Some(RewriteRouteRecord {
            kind: "replay_capability_gap".into(),
            evidence_id: "final-system-gap-evidence".into(),
            source_ref: "src/replay.rs:1".into(),
            required_change: "support the recorded exchange".into(),
            repair_id: Some(repair_id.into()),
            acceptance_kind: Some(RewriteRepairAcceptanceKind::TrafficE2eRevisionChanged),
            observed_revision: Some(fingerprint::traffic_e2e_revision().unwrap()),
            legacy_acceptance_command: None,
        });
        let gap_slice = serde_json::to_value(&before.active_slice).unwrap();
        save(root, &before);
        assert!(ready(&before));
        assert!(matches!(
            required_action(root, &before).unwrap(),
            Some(RewriteAction::PreRevalidationReviewRequired { .. })
        ));

        let report = check_pre_revalidation(options(root, root)).unwrap();
        assert_eq!(report.status, ReviewStatus::Passed);
        let checked = load(root);
        assert_eq!(
            serde_json::to_value(&checked.active_slice).unwrap(),
            gap_slice,
            "checking cannot consume the active repair"
        );
        candidate::accept(root.into(), report.report_path).unwrap();

        let mut after = load(root);
        assert!(current(root, &after));
        assert!(!completion_current(root, &after));
        assert_eq!(
            after.api_inventory[0].status,
            RewriteApiStatus::SystemRepairRequired
        );
        assert_eq!(
            serde_json::to_value(&after.parked_slices[&gap_api]).unwrap(),
            gap_slice,
            "final admission must retain the complete system repair slice"
        );
        assert_eq!(
            inventory::api_for_repair(&after, repair_id).as_deref(),
            Some(gap_api.as_str())
        );
        assert_eq!(after.api, "POST /other");
        assert_eq!(after.phase, RewritePhase::ApiPending);
        assert_eq!(
            after.pre_revalidation_review.as_ref().unwrap().remaining,
            BTreeSet::from(["POST /other".into()])
        );
        assert!(!inventory::revalidation_round::contains(&after, &gap_api));
        assert!(inventory::revalidation_round::contains(
            &after,
            "POST /other"
        ));
        assert_eq!(after.api_inventory[2].status, RewriteApiStatus::Skipped);

        complete_current(root, &mut after);
        save(root, &after);
        let restored = load(root);
        assert!(completion_current(root, &restored));
        // Loading may select the remaining repair as the active slice. Its
        // identity must survive either storage location.
        let restored_gap = if restored.api == gap_api {
            &restored.active_slice
        } else {
            &restored.parked_slices[&gap_api]
        };
        assert_eq!(serde_json::to_value(restored_gap).unwrap(), gap_slice);
        assert_eq!(
            inventory::api_for_repair(&restored, repair_id).as_deref(),
            Some(gap_api.as_str())
        );
        let status = crate::action::for_status(root, &restored).unwrap();
        assert!(!status.terminal_allowed);
        assert!(matches!(
            status.action,
            RewriteAction::Blocked { ref system_repair_apis, .. }
                if system_repair_apis
                    == &[crate::api_selector::public_api(&gap_api)]
        ));
    }
}
