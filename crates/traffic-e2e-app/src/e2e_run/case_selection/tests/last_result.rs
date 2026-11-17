use super::*;

#[test]
fn latest_result_shrinks_22_cases_to_two_dirty_cases_then_one_without_counting_skips_as_failures() {
    for old_metadata_missing in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (layout, mut inventory, iteration) = fixture(root.path());
        inventory.groups.truncate(1);
        let group = &mut inventory.groups[0];
        let seed = group.cases[0].clone();
        group.cases = (0..22)
            .map(|index| {
                let mut case = seed.clone();
                case.case_id = format!("case-{index:02}");
                case
            })
            .collect();
        let mut previous = attempt(&layout, &mut inventory.clone(), &iteration);
        previous.sequence = 11;
        for (index, case) in previous.cases.iter_mut().enumerate() {
            case.status = if index < 20 {
                CaseStatus::Passed
            } else {
                CaseStatus::Failed
            };
            case.assertion_passed = Some(true);
            case.replay_clean = Some(index < 20);
        }
        // A later Target shutdown problem does not erase independently completed Cases.
        previous.replay_finalized = false;
        previous.status = RunStatus::Interrupted;
        if old_metadata_missing {
            previous.case_selection = None;
        }
        let path = layout
            .run_root
            .join("focused")
            .join(api_directory(&inventory.groups[0].group_id))
            .join("latest/state.yaml");
        store::write_yaml(&path, &previous).unwrap();

        let mut second = attempt(&layout, &mut inventory.clone(), &iteration);
        assert_eq!(
            second
                .cases
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<Vec<_>>(),
            ["case-20", "case-21"]
        );
        assert_eq!(diagnosis(&second).unwrap()["skipped_previously_passed"], 20);
        second.sequence = 12;
        second.replay_finalized = false;
        second.cases[0].status = CaseStatus::Passed;
        second.cases[0].assertion_passed = Some(true);
        second.cases[0].replay_clean = Some(true);
        second.cases[1].status = CaseStatus::Failed;
        second.cases[1].assertion_passed = Some(true);
        second.cases[1].replay_clean = Some(false);
        save(&layout, &second);

        let third = attempt(&layout, &mut inventory.clone(), &iteration);
        assert_eq!(third.cases.len(), 1);
        assert_eq!(third.cases[0].case_id, "case-21");
        assert_eq!(third.cases[0].status, CaseStatus::Pending);
        assert_eq!(diagnosis(&third).unwrap()["skipped_previously_passed"], 21);
        validate_group(&third, &inventory.groups[0]).unwrap();
        let result = super::super::super::result::api_result(
            &layout,
            &third,
            &inventory.groups[0].group_id,
            13,
        );
        assert_eq!(result.diagnosis.counts.selected, 1);
        assert_eq!(result.diagnosis.counts.executed, 0);
        assert_eq!(result.diagnosis.counts.response_nonpassing, 0);
        let mut limit = super::super::super::failure_limit::ApiFailureLimit::new(10);
        assert!(!limit.observe(&third.cases[0].group_id, CaseStatus::Failed));
        assert!(limit.should_execute(&third.cases[0].group_id));
        let args = super::super::super::runtime::replay_case_args(&inventory, &third);
        assert_eq!(args, ["--case-id", "case-21"]);
    }
}
