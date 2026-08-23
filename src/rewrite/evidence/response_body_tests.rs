use super::*;

#[test]
fn exact_hessian2_body_offers_response_body_codec_configuration() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "comparison_observation": {
            "pointer": "$body",
            "body_diagnosis": {
                "codec": "hessian2",
                "codec_candidates": ["hessian2"],
                "configured": false
            }
        }
    });

    let hints = rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Comparison,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].capability, "hessian2");
    assert!(hints[0].hint.contains("Hessian2 candidate"));
    assert!(planners.iter().any(|planner| {
        planner.capability == "hessian2"
            && planner.command.argv.iter().any(|value| value == "hessian2")
    }));
}

#[test]
fn exact_body_offers_each_supported_codec_candidate() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "comparison_observation": {
            "pointer": "$body",
            "body_diagnosis": {
                "codec": "protobuf",
                "codec_candidates": ["protobuf", "hessian2"],
                "configured": false
            }
        }
    });

    let hints = rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Response,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(
        hints
            .iter()
            .map(|hint| hint.capability.as_str())
            .collect::<Vec<_>>(),
        vec!["protobuf", "hessian2"]
    );
    assert!(
        planners
            .iter()
            .any(|planner| planner.capability == "protobuf")
    );
    assert!(
        planners
            .iter()
            .any(|planner| planner.capability == "hessian2")
    );
}
