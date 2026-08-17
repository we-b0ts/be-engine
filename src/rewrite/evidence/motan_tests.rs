use super::*;

#[test]
fn exact_motan_hessian2_body_offers_protocol_configuration() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "comparison_observation": {
            "pointer": "$body",
            "motan": {
                "rule_kind": "motan",
                "protocol": "hessian2",
                "protocol_candidates": ["hessian2"],
                "configured": false
            }
        }
    });

    let hints = protocol_rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Comparison,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].protocol, "motan_hessian2");
    assert!(hints[0].hint.contains("Hessian2 candidate"));
    let planner = planners
        .iter()
        .find(|planner| planner.protocol == "motan_hessian2")
        .unwrap();
    assert!(planner.command.argv.iter().any(|value| value == "hessian2"));
}

#[test]
fn exact_motan_body_offers_each_supported_protocol_candidate() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "comparison_observation": {
            "pointer": "$body",
            "motan": {
                "rule_kind": "motan",
                "protocol": "protobuf",
                "protocol_candidates": ["protobuf", "hessian2"],
                "configured": false
            }
        }
    });

    let hints = protocol_rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Comparison,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(
        hints
            .iter()
            .map(|hint| hint.protocol.as_str())
            .collect::<Vec<_>>(),
        vec!["motan_protobuf", "motan_hessian2"]
    );
    assert!(planners.iter().any(|planner| {
        planner.protocol == "motan_protobuf"
            && planner.command.argv.iter().any(|value| value == "protobuf")
    }));
    assert!(planners.iter().any(|planner| {
        planner.protocol == "motan_hessian2"
            && planner.command.argv.iter().any(|value| value == "hessian2")
    }));
}

#[test]
fn configured_motan_hessian2_body_offers_unordered_lists_without_repeating_protocol_configuration()
{
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "comparison_observation": {
            "pointer": "$body",
            "motan": {
                "rule_kind": "motan",
                "protocol": "hessian2",
                "configured": true,
                "unordered_path_candidates": [{"value_path": []}]
            }
        }
    });

    let hints = protocol_rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Comparison,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );

    assert_eq!(hints.len(), 1);
    assert!(hints[0].hint.contains("value_path"));
    assert!(
        planners
            .iter()
            .all(|planner| planner.protocol != "motan_hessian2")
    );
}
