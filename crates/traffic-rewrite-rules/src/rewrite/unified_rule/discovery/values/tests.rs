use super::*;

struct DiagnosticPolicy;

struct SourcePolicy;
impl traffic_policy::PolicyProvider for SourcePolicy {
    fn descriptor(&self) -> traffic_policy::PolicyDescriptor {
        traffic_policy::PolicyDescriptor {
            id: "fixture-source",
            version: 1,
            description: "Inspect original Source acquisition evidence",
            actions: &[traffic_policy::PolicyAction::Analyze],
        }
    }
    fn analyze(
        &self,
        input: &traffic_policy::AnalysisInput<'_>,
        evidence: &dyn traffic_policy::EvidenceAccess,
    ) -> Result<Vec<traffic_policy::Finding>> {
        if input.values.is_some() {
            return Ok(Vec::new());
        }
        let source = evidence.query("source", &traffic_value::Value::Null)?;
        assert!(source[0].pointer("/endpoint").is_some());
        let raw = evidence.query("source.bytes", &traffic_value::Value::Null)?;
        assert!(matches!(&raw[0],traffic_value::Value::Bytes(bytes) if !bytes.is_empty()));
        assert!(
            evidence
                .query("target", &traffic_value::Value::Null)
                .is_err()
        );
        Ok(vec![traffic_policy::Finding {
            policy: "fixture-source".into(),
            source_path: "/endpoint".into(),
            summary: "Source response contains an address for investigation".into(),
            hint: "Trace Source consumption and review a capture rule".into(),
            proposal: Some(traffic_policy::Proposal::Document(serde_json::from_value(
                json!({
                    "format":"traffic-policy/v3","http":{"response_rewrite":[{
                        "name":"source-address","host":"config.test","method":"GET","path":"/config",
                        "policy":{"id":"documents","version":1,"options":{"rules":[{
                            "fields":[{"path":"/endpoint","format":"url"}]
                        }]}}
                    }]}
                }),
            )?)),
            requirements: vec!["source_semantics".into(), "recording".into()],
        }])
    }
}

#[test]
fn source_only_registered_analysis_can_return_a_recording_policy_document() {
    let mut policies = traffic_policy::PolicyRegistry::default();
    policies
        .register(std::sync::Arc::new(SourcePolicy))
        .unwrap();
    let mut drafts = Drafts {
        policies,
        ..Default::default()
    };
    let source = br#"{"endpoint":"http://10.0.0.1:8080"}"#;
    for (witness, target) in [
        ("missing-target", None),
        ("equal-target", Some(source.as_slice())),
    ] {
        drafts
            .observe(
                source,
                target,
                json!({"surface":"dependency.response"}),
                witness,
                clocks(),
                None,
                None,
            )
            .unwrap();
    }
    let candidates = drafts.candidates();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["location_count"], 2);
    assert_eq!(
        candidates[0]["draft_policy"]["http"]["response_rewrite"][0]["policy"]["id"],
        "documents"
    );
    assert_eq!(candidates[0]["source_proof_required"], true);
    assert_eq!(candidates[0]["plan_ready"], false);
}

#[test]
fn source_only_field_locations_generalize_arrays_and_preserve_escaped_object_keys() {
    let source = serde_json::from_value(json!({"a/b":[{"~key":1}]})).unwrap();
    let location = JsonLocation::from_source(&source, "/a~1b/0/~0key").unwrap();
    assert_eq!(location.pointer, "/a~1b/0/~0key");
    assert_eq!(location.pattern, "/a~1b/*/~0key");
}

#[test]
fn automatic_codecs_reach_registered_hints_and_keep_opaque_bytes_scalar() {
    let mut drafts = installed_drafts();
    drafts
        .observe(
            b"a,b,a",
            Some(b"b,a,a"),
            json!({"surface":"api.response","slot":"body"}),
            "plain-string",
            clocks(),
            None,
            None,
        )
        .unwrap();
    let candidates = drafts.candidates();
    assert!(candidates.is_empty());
    let finding = drafts
        .findings
        .iter()
        .find(|finding| finding["policy"] == "unordered-joined-string")
        .unwrap();
    assert_eq!(finding["requires_value_binding"], true);
    assert_eq!(
        finding["proposal"]["value"]["id"],
        "unordered-joined-string"
    );

    let mut opaque = installed_drafts();
    opaque
        .observe(
            &[255, 254],
            Some(&[254, 255]),
            json!({"surface":"dependency.request"}),
            "opaque-bytes",
            clocks(),
            None,
            None,
        )
        .unwrap();
    assert!(opaque.candidates().is_empty());
    assert_eq!(opaque.examined, 1);
}

impl traffic_policy::PolicyProvider for DiagnosticPolicy {
    fn descriptor(&self) -> traffic_policy::PolicyDescriptor {
        traffic_policy::PolicyDescriptor {
            id: "fixture-diagnostic",
            version: 1,
            description: "Diagnose a value without proposing a rule",
            actions: &[traffic_policy::PolicyAction::Analyze],
        }
    }

    fn analyze(
        &self,
        input: &traffic_policy::AnalysisInput<'_>,
        _: &dyn traffic_policy::EvidenceAccess,
    ) -> Result<Vec<traffic_policy::Finding>> {
        let Some(pair) = &input.values else {
            return Ok(Vec::new());
        };
        Ok(vec![traffic_policy::Finding {
            policy: "fixture-diagnostic".into(),
            source_path: pair.source_path.into(),
            summary: "Source and Target require investigation".into(),
            hint: "Inspect the field's Source construction".into(),
            proposal: None,
            requirements: vec!["source_semantics".into()],
        }])
    }
}

#[test]
fn discovery_retains_registered_diagnostics_without_a_rule_proposal() {
    let mut policies = traffic_policy::PolicyRegistry::default();
    policies
        .register(std::sync::Arc::new(DiagnosticPolicy))
        .unwrap();
    let mut drafts = Drafts {
        policies,
        ..Default::default()
    };
    observe(&mut drafts, json!(1), json!(2), "witness");
    assert!(drafts.candidates().is_empty());
    assert_eq!(drafts.findings.len(), 1);
    assert_eq!(drafts.findings[0]["policy"], "fixture-diagnostic");
    assert_eq!(drafts.findings[0]["witness_id"], "witness");
    assert_eq!(drafts.findings[0]["location"], base());
    assert_eq!(
        drafts.findings[0]["requirements"],
        json!(["source_semantics"])
    );
    observe(&mut drafts, json!(1), json!(2), "witness");
    assert_eq!(drafts.findings.len(), 1);
    let mut removed = Drafts::default();
    observe(&mut removed, json!(1), json!(2), "witness");
    assert!(removed.findings.is_empty());
}

#[test]
fn registered_analysis_observes_values_handled_by_automatic_time_comparison() {
    let mut policies = traffic_policy::PolicyRegistry::default();
    policies
        .register(std::sync::Arc::new(DiagnosticPolicy))
        .unwrap();
    let mut drafts = Drafts {
        policies,
        ..Default::default()
    };
    observe(
        &mut drafts,
        json!("2026-10-16T00:00:00Z"),
        json!("2026-10-16T00:01:00Z"),
        "clock-witness",
    );
    assert!(drafts.candidates().is_empty());
    assert_eq!(drafts.findings.len(), 1);
    assert_eq!(drafts.findings[0]["policy"], "fixture-diagnostic");
}

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
            &serde_json::from_value(source).unwrap(),
            &serde_json::from_value(target).unwrap(),
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
    let mut drafts = installed_drafts();
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
    let mut drafts = installed_drafts();
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
    let mut drafts = installed_drafts();
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
    let mut first = installed_drafts();
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
    let mut second = installed_drafts();
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
    let mut first = installed_drafts();
    observe(&mut first, value(0), value(60), "case");
    let mut next = Drafts {
        summary_offset: LIMIT,
        ..installed_drafts()
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
        ..installed_drafts()
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
    let mut isolated = installed_drafts();
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
    let mut drafts = installed_drafts();
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
    let mut drafts = installed_drafts();
    observe(&mut drafts, block_times(1, 0), block_times(2, 60), "case");
    assert!(drafts.values.is_empty());
}

#[test]
fn removing_time_registration_removes_temporal_drafts() {
    let mut removed = Drafts::default();
    observe(&mut removed, block_times(1, 0), block_times(1, 60), "case");
    assert!(removed.values.is_empty());
    assert!(removed.findings.is_empty());
    let mut installed = installed_drafts();
    observe(
        &mut installed,
        block_times(1, 0),
        block_times(1, 60),
        "case",
    );
    assert_eq!(installed.values.len(), 1);
    assert_eq!(installed.values[0]["mechanism"], "time");
}

#[test]
fn builtin_standard_strings_do_not_offer_redundant_rule_drafts() {
    for (source, target) in [
        ("2026-10-16 08:00:01", "2026-10-16 08:01:01"),
        ("2026-10-16T08:00:01", "2026-10-16T08:01:01"),
        ("2026-10-16T00:00:01Z", "2026-10-16T00:01:01Z"),
    ] {
        let mut drafts = installed_drafts();
        observe(
            &mut drafts,
            json!({"at":source}),
            json!({"at":target}),
            "case",
        );
        assert!(drafts.candidates().is_empty());
        let mut invalid = installed_drafts();
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
    let mut drafts = installed_drafts();
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
                &serde_json::from_value(json!({"at":1_760_572_800_i64})).unwrap(),
                &serde_json::from_value(json!({"at":1_760_572_860_i64})).unwrap(),
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
        let mut drafts = installed_drafts();
        drafts
            .collect(
                &serde_json::from_value(json!({"at":1_792_108_830_i64})).unwrap(),
                &serde_json::from_value(json!({"at":target})).unwrap(),
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
