use super::*;

#[test]
fn docx_candidate_points_to_the_reviewed_timestamp_planner() {
    let target = tempfile::tempdir().unwrap();
    let facts = serde_json::json!({
        "representative": {"response_difference": {
            "pointer": "$body",
            "body_diagnosis": {
                "codec": "docx",
                "codec_candidates": ["docx"],
                "configured": false
            }
        }}
    });
    let hints = rule_hints(target.path(), QUERY_REPRESENTATIVES, &facts);
    let planners = applicable_rule_planners(
        target.path(),
        RewriteIssueKind::Response,
        QUERY_REPRESENTATIVES,
        &facts,
        "evidence-current",
    );
    assert_eq!(hints[0].capability, "docx");
    assert!(hints[0].hint.contains("DOCX OPC"));
    let planner = planners
        .iter()
        .find(|planner| planner.capability == "docx")
        .unwrap();
    assert!(planner.command.argv.iter().any(|value| value == "--file"));
}
