use super::*;

fn clocks() -> AnchorClocks {
    AnchorClocks::for_response(
        crate::value_contract::time::ClockPair::default(),
        crate::value_contract::time::ClockPair {
            source: Some("2026-10-16T00:00:00Z".parse().unwrap()),
            target: Some("2026-10-16T00:01:00Z".parse().unwrap()),
        },
    )
}

fn base() -> Value {
    json!({"surface":"api.response","match":{"api":"GET /api"},"slot":"body","codec":"json"})
}

fn observe(drafts: &mut Drafts, source: Value, target: Value, witness: &str) {
    drafts
        .collect(
            &source,
            &target,
            &JsonLocation::default(),
            &base(),
            witness,
            clocks(),
            0,
        )
        .unwrap();
}

fn block_times(count: usize, offset: i64) -> Value {
    json!({"blocks": (0..count).map(|index|
        json!({"timestamp":1_760_572_800_i64 + index as i64 + offset,"id":"stable"})
    ).collect::<Vec<_>>()})
}

#[test]
fn real_array_elements_and_cases_share_one_proof_required_draft() {
    let mut drafts = Drafts::default();
    observe(&mut drafts, block_times(6, 0), block_times(6, 60), "case-a");
    observe(&mut drafts, block_times(2, 0), block_times(2, 60), "case-b");
    let candidates = drafts.candidates();
    assert_eq!(drafts.seen.len(), 1);
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(
        candidate["draft_policy"]["json"]["fields"]["/blocks/*/timestamp"]["formats"],
        json!(["unix_seconds"])
    );
    assert_eq!(candidate["location_count"], 8);
    assert_eq!(
        candidate["locations"][0],
        json!({"witness_id":"case-a","pointer":"/blocks/0/timestamp"})
    );
    assert_eq!(
        candidate["locations"][7],
        json!({"witness_id":"case-b","pointer":"/blocks/1/timestamp"})
    );
    assert_eq!(candidate["plan_ready"], false);
    assert_eq!(candidate["source_proof_required"], true);
    assert_eq!(candidate["section_update"], "add");
    assert!(candidate.get("preserve_existing_fields").is_none());
    assert_eq!(candidate["mechanism"], "time");
    let policy = serde_json::from_value(candidate["draft_policy"].clone()).unwrap();
    crate::policy::compile_policy(&policy).unwrap();
}

#[test]
fn numeric_object_keys_remain_literal_and_do_not_declare_an_array_clock() {
    let mut drafts = Drafts::default();
    observe(
        &mut drafts,
        json!({"blocks":{"0":{"at":1_760_572_800_i64},"1":{"at":1_760_572_801_i64}}}),
        json!({"blocks":{"0":{"at":1_760_572_860_i64},"1":{"at":1_760_572_861_i64}}}),
        "case",
    );
    assert_eq!(drafts.values.len(), 2);
    for (index, candidate) in drafts.values.iter().enumerate() {
        let pointer = format!("/blocks/{index}/at");
        let contract = &candidate["draft_policy"]["json"]["fields"][&pointer];
        assert_eq!(contract["kind"], "time");
        assert!(contract.get("clock_scope").is_none());
    }
}

#[test]
fn nested_arrays_keep_real_array_boundaries_and_escaped_object_members() {
    let mut drafts = Drafts::default();
    let value = |offset: i64| json!({"0":[{"~/":[{"at":1_760_572_800_i64+offset}]}]});
    observe(&mut drafts, value(0), value(60), "case");
    let candidates = drafts.candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0]["draft_policy"]["json"]["fields"]["/0/*/~0~1/*/at"]["formats"],
        json!(["unix_seconds"])
    );
    assert_eq!(candidates[0]["locations"][0]["pointer"], "/0/0/~0~1/0/at");
}

#[test]
fn array_draft_ids_ignore_case_order_and_element_count_and_bound_location_summaries() {
    let mut first = Drafts::default();
    observe(
        &mut first,
        block_times(25, 0),
        block_times(25, 60),
        "case-many",
    );
    observe(
        &mut first,
        block_times(1, 0),
        block_times(1, 60),
        "case-one",
    );
    let mut second = Drafts::default();
    observe(
        &mut second,
        block_times(1, 0),
        block_times(1, 60),
        "case-one",
    );
    observe(
        &mut second,
        block_times(25, 0),
        block_times(25, 60),
        "case-many",
    );
    assert_eq!(
        first.values[0]["candidate_id"],
        second.values[0]["candidate_id"]
    );
    assert_eq!(
        first.candidates(),
        second
            .candidates()
            .into_iter()
            .map(|mut v| {
                v["witness_id"] = json!("case-many");
                v
            })
            .collect::<Vec<_>>()
    );
    let candidate = &first.candidates()[0];
    assert_eq!(candidate["location_count"], 26);
    assert_eq!(candidate["locations"].as_array().unwrap().len(), LIMIT);
    assert_eq!(candidate["locations_omitted"], 6);
    observe(
        &mut first,
        block_times(25, 0),
        block_times(25, 60),
        "case-many",
    );
    assert_eq!(first.candidates()[0]["location_count"], 26);
}

#[test]
fn wildcard_candidate_paging_keeps_ids_and_no_identity_drafts_are_inferred() {
    let value = |offset: i64| {
        Value::Object((0..25).map(|index| (
        format!("field{index:02}"), json!([{"at":1_760_572_800_i64+offset,"id":if offset==0 {"old"} else {"new"}}])
    )).collect())
    };
    let mut first = Drafts::default();
    observe(&mut first, value(0), value(60), "case");
    let mut next = Drafts {
        summary_offset: LIMIT,
        ..Default::default()
    };
    observe(&mut next, value(0), value(60), "case");
    assert_eq!(first.seen.len(), 25);
    assert_eq!(next.seen, first.seen);
    assert_eq!(first.values.len(), LIMIT);
    assert_eq!(next.values.len(), 5);
    assert!(
        first
            .values
            .iter()
            .chain(&next.values)
            .all(|c| c["mechanism"] == "time" && c["plan_ready"] == false)
    );
    let mut all = Drafts {
        summary_offset: 0,
        ..Default::default()
    };
    observe(&mut all, value(0), value(60), "other-case");
    assert_eq!(
        first.values[0]["candidate_id"],
        all.values[0]["candidate_id"]
    );
    assert!(
        next.values[0]["draft_policy"]["json"]["fields"]
            .get("/field20/*/at")
            .is_some()
    );
    let mut isolated = Drafts::default();
    observe(
        &mut isolated,
        json!({"field20":[{"at":1_760_572_800_i64,"id":"old"}]}),
        json!({"field20":[{"at":1_760_572_860_i64,"id":"new"}]}),
        "independent-case",
    );
    assert_eq!(
        next.values[0]["candidate_id"],
        isolated.values[0]["candidate_id"]
    );
}

#[test]
fn repeated_unordered_fields_merge_without_inventing_time_or_identity_permissions() {
    let mut drafts = Drafts::default();
    observe(
        &mut drafts,
        json!({"items":[{"members":[1,2,2],"id":"a"},{"members":[3,4],"id":"b"}]}),
        json!({"items":[{"members":[2,1,2],"id":"a"},{"members":[4,3],"id":"b"}]}),
        "case",
    );
    let candidates = drafts.candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["location_count"], 2);
    assert_eq!(
        candidates[0]["draft_policy"]["json"]["fields"]["/items/*/members"],
        json!({"kind":"unordered"})
    );
    assert_eq!(candidates[0]["plan_ready"], false);
}

#[test]
fn changed_array_cardinality_does_not_supply_a_time_or_unordered_draft() {
    let mut drafts = Drafts::default();
    observe(&mut drafts, block_times(1, 0), block_times(2, 60), "case");
    assert!(drafts.values.is_empty());
}

#[test]
fn builtin_standard_strings_do_not_offer_redundant_rule_drafts() {
    for (source, target) in [
        ("2026-10-16 08:00:01", "2026-10-16 08:01:01"),
        ("2026-10-16T08:00:01", "2026-10-16T08:01:01"),
        ("2026-10-16T00:00:01Z", "2026-10-16T00:01:01Z"),
    ] {
        let mut drafts = Drafts::default();
        observe(
            &mut drafts,
            json!({"at":source}),
            json!({"at":target}),
            "case",
        );
        assert!(drafts.candidates().is_empty());
        let mut invalid = Drafts::default();
        observe(
            &mut invalid,
            json!({"at":source}),
            json!({"at":"2026-10-17 08:01:01"}),
            "wrong-offset",
        );
        assert!(invalid.values.is_empty());
    }
}

#[test]
fn format_drafts_deduplicate_across_api_and_carrier_positions() {
    let mut drafts = Drafts::default();
    for (surface, api) in [
        ("api.response", "GET /one"),
        ("dependency.request", "POST /two"),
    ] {
        let base = json!({"surface":surface,"match":{"api":api},"slot":"body"});
        let clocks = if surface == "api.response" {
            clocks()
        } else {
            AnchorClocks::for_request(
                Default::default(),
                clocks().observation(),
                Default::default(),
            )
        };
        drafts
            .collect(
                &json!({"at":1_760_572_800_i64}),
                &json!({"at":1_760_572_860_i64}),
                &JsonLocation::default(),
                &base,
                api,
                clocks,
                0,
            )
            .unwrap();
    }
    assert_eq!(drafts.seen.len(), 1);
    let candidates = drafts.candidates();
    assert_eq!(candidates[0]["location_count"], 2);
    assert!(candidates[0]["draft_policy"].get("rules").is_none());
}

#[test]
fn response_drafts_allow_elapsed_sampling_without_borrowing_missing_event_clocks() {
    let pair = |source, target| crate::value_contract::time::ClockPair {
        source: chrono::DateTime::from_timestamp(source, 0),
        target: chrono::DateTime::from_timestamp(target, 0),
    };
    for (target, completion_available) in [
        (1_792_108_950_i64, true),
        (1_792_108_890, true),
        (1_792_108_890, false),
    ] {
        let clocks = AnchorClocks::for_response(
            pair(1_792_108_800, 1_792_108_860),
            if completion_available {
                pair(1_792_108_830, 1_792_108_950)
            } else {
                Default::default()
            },
        );
        let mut drafts = Drafts::default();
        drafts
            .collect(
                &json!({"at":1_792_108_830_i64}),
                &json!({"at":target}),
                &JsonLocation::default(),
                &base(),
                "independent-response",
                clocks,
                0,
            )
            .unwrap();
        assert_eq!(drafts.candidates().len(), usize::from(completion_available));
    }
}
