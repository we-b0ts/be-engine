use traffic_policy::PolicyRegistry;
use traffic_policy_content::body;
use traffic_policy_schema::response::{
    ProtobufFieldPath, ProtobufRepeatedElementType, ProtobufUnorderedPath, ResponseBodyCodec,
    ResponseBodyRuleMatch, ResponseBodyUnorderedPath,
};

fn rule() -> ResponseBodyRuleMatch {
    ResponseBodyRuleMatch {
        id: "source-collection".into(),
        api: "/example".into(),
        codec: ResponseBodyCodec::Protobuf,
        unordered_paths: vec![ResponseBodyUnorderedPath::Protobuf(ProtobufUnorderedPath {
            field_path: ProtobufFieldPath(vec![1]),
            display_path: "items".into(),
            element_type: ProtobufRepeatedElementType::String,
            source_evidence: "Source constructs a collection".into(),
        })],
        unordered_joined_string_paths: vec![],
        docx_timestamps: vec![],
    }
}

#[test]
fn supplied_catalog_controls_content_hints_and_rule_execution() {
    let source = b"\x0a\x01a\x0a\x01b\x10\x01";
    let target = b"\x0a\x01b\x0a\x01a\x10\x01";
    let empty = PolicyRegistry::default();
    let unconfigured = body::discover(&empty, source, target).unwrap().unwrap();
    assert!(unconfigured.unordered_path_candidates.is_empty());
    assert!(!unconfigured.candidates_explain_all_differences);
    assert!(body::evaluate(&empty, &rule(), source, target, Default::default()).is_err());

    let installed = traffic_extensions::policies();
    let diagnosed = body::discover(installed, source, target).unwrap().unwrap();
    assert!(!diagnosed.unordered_path_candidates.is_empty());
    let (matched, _) =
        body::evaluate(installed, &rule(), source, target, Default::default()).unwrap();
    assert!(matched);
    let (matched, _) = body::evaluate(
        installed,
        &rule(),
        source,
        b"\x0a\x01b\x0a\x01a\x10\x02",
        Default::default(),
    )
    .unwrap();
    assert!(!matched);
}

#[test]
fn temporal_content_requires_the_installed_temporal_policy() {
    use traffic_policy_schema::response::{ResponseDurationUnit, ResponseTimeRule};
    let clocks = traffic_policy_content::time::RequestTimes {
        source: chrono::DateTime::from_timestamp(100, 0),
        target: chrono::DateTime::from_timestamp(100, 0),
    };
    let rule = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Seconds,
    };
    assert!(
        traffic_policy_content::time::compare(
            &PolicyRegistry::default(),
            rule,
            &serde_json::json!(12),
            &serde_json::json!(12),
            clocks
        )
        .is_err()
    );
    assert!(
        traffic_policy_content::time::compare(
            traffic_extensions::policies(),
            rule,
            &serde_json::json!(12),
            &serde_json::json!(12),
            clocks
        )
        .is_ok()
    );
}
