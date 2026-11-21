//! Retired authoring cannot overwrite a current policy or immutable evidence.
use super::*;
use serde_json::json;
#[path = "tests/json_arrays.rs"]
mod json_arrays;

pub(super) struct RetiredFixture {
    _temp: tempfile::TempDir,
    pub policy: PathBuf,
    pub evidence: PathBuf,
}
impl RetiredFixture {
    pub(super) fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let policy = temp.path().join("policy.yaml");
        let evidence = temp.path().join("dependencies.jsonl");
        fs::write(
            &policy,
            "# preserved policy\nformat: traffic-policy/v3\nrules: []\n",
        )
        .unwrap();
        fs::write(&evidence, b"immutable Source and Target witnesses\n").unwrap();
        Self {
            _temp: temp,
            policy,
            evidence,
        }
    }
    pub(super) fn check<T>(&self, run: impl FnOnce() -> Result<T>) {
        let before = [
            fs::read(&self.policy).unwrap(),
            fs::read(&self.evidence).unwrap(),
        ];
        let error = run()
            .err()
            .expect("retired authoring must reject the request");
        assert!(
            error
                .to_string()
                .contains("legacy rule authoring is retired"),
            "{error:#}"
        );
        assert!(error.to_string().contains("traffic-policy/v3"));
        assert_eq!(fs::read(&self.policy).unwrap(), before[0]);
        assert_eq!(fs::read(&self.evidence).unwrap(), before[1]);
    }
    pub(super) fn response(&self, kind: ResponseRuleKind) -> ResponseRuleFeedback {
        ResponseRuleFeedback {
            policy_path: self.policy.clone(),
            kind,
            time: None,
            api: "GET /api".into(),
            json_pointers: vec!["/id".into()],
            source_evidence: Some("src/source.rs: generated field".into()),
            source_example: None,
            target_example: None,
            separator: None,
            assertion_report: self.evidence.clone(),
            aggregate_report: self.evidence.clone(),
        }
    }
    pub(super) fn identity(&self) -> DynamicValueRuleFeedback {
        DynamicValueRuleFeedback {policy_path:self.policy.clone(),replay_report:self.evidence.clone(),rule:serde_json::from_value(json!({"id":"generated-id","api":"/items","targets":[{"host":"db.test","port":3306}],"capture":{"protocol":"mysql","target":{"host":"db.test","port":3306},"database":"app","sql":"INSERT INTO items (id, created) VALUES (?, ?)","value_index":0},"source_evidence":"src/source.rs generates this item identity"})).unwrap()}
    }
}
#[test]
fn retired_response_planners_leave_policy_and_evidence_unchanged() {
    for kind in [
        ResponseRuleKind::Uuid,
        ResponseRuleKind::Random,
        ResponseRuleKind::Unordered,
        ResponseRuleKind::UnorderedJoinedString,
    ] {
        let fixture = RetiredFixture::new();
        fixture.check(|| plan_response_rule(fixture.response(kind)));
    }
}

#[test]
fn retired_pending_response_plan_cannot_overwrite_a_unified_policy() {
    let fixture = RetiredFixture::new();
    let report = ResponseRuleReport {
        policy: fixture.policy.clone(),
        policy_fingerprint: "old-plan".into(),
        assertion_report: None,
        assertion_fingerprint: None,
        aggregate_report: None,
        aggregate_fingerprint: None,
        kind: ResponseRuleKind::Uuid,
        time: None,
        api: "GET /api".into(),
        json_pointers: vec!["/id".into()],
        source_evidence: Some("src/source.rs: generated UUID".into()),
        source_example: None,
        target_example: None,
        separator: None,
        matching_cases: 1,
        selected_difference_cases: 1,
        residual_difference_cases: 0,
        unselected_difference_pointers: vec![],
        aggregate_dirty: Some(false),
        changed: true,
        applied: false,
        added_rule_ids: vec!["old".into()],
        diff: String::new(),
    };
    let plan = ResponseRulePlan {
        report,
        witnesses: vec![],
    };
    fixture.check(|| plan.apply());
}
