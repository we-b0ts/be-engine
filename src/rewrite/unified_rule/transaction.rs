//! Public coordinator integration, using a published focused attempt and real store.
use super::*;
use crate::rewrite::model::RewriteAttemptSummary;
use crate::rewrite::worker::{self, RewriteWorkerConfirmOptions};
use crate::rewrite::{
    RewriteWorkScope, apply_rewrite_rule, query_rewrite_evidence, query_rewrite_evidence_for_scope,
    recover_rewrite_rule_plan,
};

#[path = "transaction_dependency.rs"]
mod dependency_transaction;
#[path = "transaction_native.rs"]
mod native_transaction;
#[path = "transaction_recovery.rs"]
mod recovery_transaction;

struct Fixture {
    target: tempfile::TempDir,
    proposal: PathBuf,
    paths: crate::E2eResponseRuleEvidence,
}

fn write(path: &Path, value: serde_json::Value) {
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

fn body(value: serde_json::Value) -> serde_json::Value {
    json!({"encoding":"utf8","data":value.to_string(),"truncated":false})
}

fn raw_body(bytes: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    json!({"encoding":"base64","data":base64::engine::general_purpose::STANDARD.encode(bytes),"truncated":false})
}

impl Fixture {
    fn new() -> Self {
        let target = crate::rewrite::worker::tests::configured_target();
        let root = target.path();
        let project_path = root.join(".traffic-e2e/project.yaml");
        let mut project: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(&project_path).unwrap()).unwrap();
        project["project"]["policy"] = json!(".traffic-e2e/policy.yaml");
        project["recorder"]["dns_mock"]["enabled"] = json!(true);
        project["recorder"]["tcp_gateway"]["enabled"] = json!(true);
        project["recorder"]["tcp_gateway"]["record_http"] = json!(true);
        project["recorder"]["http_gateway"]["enabled"] = json!(true);
        project["recorder"]["http_gateway"]["ready"]["enabled"] = json!(true);
        project["project"]
            .as_object_mut()
            .unwrap()
            .remove("recording");
        project["project"]["replay"]
            .as_object_mut()
            .unwrap()
            .remove("policy");
        fs::write(&project_path, serde_yaml::to_string(&project).unwrap()).unwrap();
        fs::write(
            root.join(".traffic-e2e/Dockerfile.target"),
            "FROM scratch\n",
        )
        .unwrap();
        let policy = root.join(".traffic-e2e/policy.yaml");
        fs::write(&policy, "format: traffic-policy/v1\nrules: []\n").unwrap();
        let source = root.join(".traffic-e2e/local/artifacts/recordings/recording");
        let case = source.join("apis/api/case-1");
        fs::create_dir_all(&case).unwrap();
        write(
            &source.join("recording-run.json"),
            json!({"status":"completed"}),
        );
        write(
            &case.join("request.json"),
            json!({"timestamp":"2026-10-16T00:00:00Z","method":"GET","uri":"/api","body":body(json!({}))}),
        );
        fs::write(case.join("dependencies.jsonl"), "").unwrap();
        let now = "2026-10-16T00:01:00Z".parse().unwrap();
        let paths = crate::e2e_run::jwt_evidence::test_support::install_attempt(
            root,
            &source,
            &[(case.clone(), 200, 200)],
            now,
        );
        let latest = paths.replay.parent().unwrap().parent().unwrap();
        let run_root = latest
            .ancestors()
            .find(|p| p.file_name().is_some_and(|n| n == "focused"))
            .unwrap()
            .parent()
            .unwrap();
        write(
            &case.join("expected-response.json"),
            json!({"status":200,"body":body(json!({"members":[1,2],"business":"exact"}))}),
        );
        let actual = latest.join("reports/case-1.json");
        write(
            &actual,
            json!({"version":1,"status":200,"body":body(json!({"members":[2,1],"business":"exact"})),"request_sent_at":now}),
        );
        let grouped = crate::case_group::ensure_case_group(crate::CaseGroupOptions {
            case_source: source.clone(),
            case_dir: source.join("apis"),
            method: "GET".into(),
            source_route: "/api".into(),
            pattern: None,
            source_revision: "source".into(),
            output: run_root.join("case-groups.json"),
            recorder_config: None,
        })
        .unwrap();
        let fingerprint = crate::validate_replay_policy(&policy).unwrap().fingerprint;
        let state_path = latest.join("state.yaml");
        let mut focused: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        focused["session_id"] = json!(uuid::Uuid::nil().to_string());
        focused["case_inventory_id"] = json!(grouped.case_inventory_id);
        let detail = latest.join("reports/assertion-detail.json");
        write(
            &detail,
            json!({"case_id":"case-1","expected_response_path":case.join("expected-response.json"),"actual_response_path":actual,
            "expected_response_fingerprint":crate::verification_progress::fingerprint(&fs::read(case.join("expected-response.json")).unwrap()),
            "actual_response_fingerprint":crate::verification_progress::fingerprint(&fs::read(&actual).unwrap())}),
        );
        let summary = &mut focused["cases"][0]["response_assertion"];
        summary["detail_report"] = json!(detail);
        summary["detail_fingerprint"] = json!(crate::verification_progress::fingerprint(
            &fs::read(&detail).unwrap()
        ));
        summary["policy_fingerprint"] = json!(fingerprint);
        write(
            &paths.assertions,
            json!({"case_source":source,"policy_fingerprint":fingerprint,"expected_response":"assertions_only","assertion_mode":"runner_owned",
            "cases":[{"case_id":"case-1","response":summary}]}),
        );
        focused["replay_finalized"] = json!(true);
        focused["aggregate_complete"] = json!(true);
        fs::write(&state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
        write(
            &paths.replay,
            json!({"finalized":true,"replay_policy":{"fingerprint":fingerprint},"cases":[{"case_id":"case-1","case_dir":case}]}),
        );
        write(
            &paths.aggregate,
            json!({"complete":true,"case_source":source,"selected_case_ids":["case-1"]}),
        );
        let proposal = root.join(".traffic-e2e/local/rule.yaml");
        write(&proposal, super::rule());
        let mut state = crate::rewrite::worker::tests::implementation_state_with_inventory(false);
        state.case_source = Some(source);
        state.source_revision = Some("source".into());
        state.case_inventory_id = Some(grouped.case_inventory_id);
        state.group_id = Some("GET /api".into());
        state.attempts.push(serde_json::from_value::<RewriteAttemptSummary>(json!({"attempt":1,"passed":false,
            "engine_fingerprint":crate::build_info::ENGINE_FINGERPRINT,"gates":{"responses":"nonpassing","replay":"complete","dependencies":"clean"},
            "counts":{"selected":1,"executed":1,"response_passed":0,"response_nonpassing":1,"response_incomplete":0}})).unwrap());
        state.replay_identity = Some(fingerprint::replay_identity(root).unwrap());
        RewriteStore::new(root).unwrap().save(&state).unwrap();
        Self {
            target,
            proposal,
            paths,
        }
    }

    fn root(&self) -> &Path {
        self.target.path()
    }
    fn context(&self) -> RewriteContext {
        RewriteContext {
            target_root: self.root().into(),
        }
    }
    fn store(&self) -> RewriteStore {
        RewriteStore::new(self.root()).unwrap()
    }
    fn state(&self) -> RewriteState {
        self.store().load().unwrap().unwrap()
    }
    fn policy(&self) -> PathBuf {
        self.root().join(".traffic-e2e/policy.yaml")
    }
    fn confirm(&self) {
        worker::confirm(RewriteWorkerConfirmOptions {
            target_root: self.root().into(),
            work_scope: RewriteWorkScope::Api { api: "/api".into() },
            worktree: Some(self.root().into()),
            agent_handle: "rule-worker".into(),
            agent_name: None,
        })
        .unwrap();
    }
    fn evidence(&self) -> super::super::super::evidence_model::RewriteEvidenceReport {
        let overview = query_rewrite_evidence_for_scope(
            self.context(),
            &RewriteWorkScope::Api { api: "/api".into() },
        )
        .unwrap();
        let hint = overview
            .rule_hints
            .iter()
            .find(|h| h.capability == "unified_value_contract")
            .unwrap();
        let id = hint.help.argv.last().unwrap();
        query_rewrite_evidence(self.context(), id).unwrap()
    }
    fn plan(&self) -> Result<RewriteRuleReport> {
        plan_rewrite_unified_rule(
            self.context(),
            RewriteUnifiedRulePlanOptions {
                file: self.proposal.clone(),
                evidence_id: self.evidence().evidence_id,
            },
        )
    }

    fn replace_response_bodies(&self, source: &[u8], target: &[u8]) {
        let mut assertions: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.paths.assertions).unwrap()).unwrap();
        let summary = &mut assertions["cases"][0]["response"];
        let expected = summary["expected_response"].as_str().unwrap().to_owned();
        let actual = summary["actual_response"].as_str().unwrap().to_owned();
        let detail_path = summary["detail_report"].as_str().unwrap().to_owned();
        write(
            Path::new(&expected),
            json!({"status":200,"body":raw_body(source)}),
        );
        write(
            Path::new(&actual),
            json!({"version":1,"status":200,"body":raw_body(target),"request_sent_at":"2026-10-16T00:01:00Z"}),
        );
        let mut detail: serde_json::Value =
            serde_json::from_slice(&fs::read(&detail_path).unwrap()).unwrap();
        detail["expected_response_fingerprint"] = json!(crate::verification_progress::fingerprint(
            &fs::read(&expected).unwrap()
        ));
        detail["actual_response_fingerprint"] = json!(crate::verification_progress::fingerprint(
            &fs::read(&actual).unwrap()
        ));
        write(Path::new(&detail_path), detail);
        summary["detail_fingerprint"] = json!(crate::verification_progress::fingerprint(
            &fs::read(&detail_path).unwrap()
        ));
        let state_path = self
            .paths
            .replay
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("state.yaml");
        let mut focused: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        focused["cases"][0]["response_assertion"] = summary.clone();
        fs::write(state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
        write(&self.paths.assertions, assertions);
    }
}

#[test]
fn protobuf_uses_the_same_public_transaction_and_retains_unknown_business_fields() {
    for changed_remainder in [false, true] {
        let fixture = Fixture::new();
        let mut proposed = super::rule();
        proposed["codec"] = json!({"kind":"protobuf","fields":{"/members":{"field_path":[1],"field_type":"string","repeated":true}}});
        write(&fixture.proposal, proposed);
        let source = b"\x0a\x03one\x0a\x03two\x12\x05exact";
        let target = if changed_remainder {
            b"\x0a\x03two\x0a\x03one\x12\x05wrong".as_slice()
        } else {
            b"\x0a\x03two\x0a\x03one\x12\x05exact".as_slice()
        };
        fixture.replace_response_bodies(source, target);
        fixture.confirm();
        let evidence = fixture.evidence();
        assert!(evidence.facts["candidates"].as_array().unwrap().is_empty());
        assert_eq!(
            evidence.facts["source_entry"]["bindings"][0]["needs_schema"],
            true
        );
        let plan = fixture.plan();
        if changed_remainder {
            assert!(plan.is_err());
            assert!(fixture.state().rule_plan.is_none());
        } else {
            let plan = plan.unwrap();
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                1
            );
            apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        }
    }
}

#[test]
fn public_discover_plan_apply_keeps_issue_and_requires_real_replay() {
    let fixture = Fixture::new();
    fixture.confirm();
    let evidence = fixture.evidence();
    assert_eq!(
        evidence.facts["candidates"][0]["draft_rule"]["contract"]["/members"]["kind"],
        "unordered"
    );
    assert!(
        evidence
            .rule_hints
            .iter()
            .any(|h| h.capability == "unified_value_contract")
    );
    let original = fs::read(fixture.policy()).unwrap();
    let plan = fixture.plan().unwrap();
    assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
        1
    );
    assert_eq!(plan.traffic_e2e_report["verified"], false);
    let issue = fixture.state().active_issue.clone();
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    assert_eq!(
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap()
            .rules
            .len(),
        1
    );
    let state = fixture.state();
    assert!(state.rule_plan.is_none() && state.rule_replay_pending && !state.e2e_current);
    assert_eq!(
        serde_json::to_value(&state.active_issue).unwrap(),
        serde_json::to_value(issue).unwrap()
    );
    assert!(!state.attempts.last().unwrap().passed);
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
}

#[test]
fn incomplete_source_inventory_and_changed_actual_bytes_cannot_plan() {
    for source_gap in [true, false] {
        let fixture = Fixture::new();
        fixture.confirm();
        if source_gap {
            write(
                &fixture.paths.aggregate,
                json!({"complete":true,"case_source":fixture.state().case_source,"selected_case_ids":[]}),
            );
        } else {
            let actual = fixture.paths.replay.parent().unwrap().join("case-1.json");
            write(
                &actual,
                json!({"status":200,"body":body(json!({"members":[2,1],"business":"changed"}))}),
            );
        }
        assert!(fixture.plan().is_err());
        assert!(fixture.state().rule_plan.is_none());
        assert!(
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
                .unwrap()
                .rules
                .is_empty()
        );
    }
}

#[test]
fn complete_source_with_missing_target_is_explicitly_unvalidated_until_replay() {
    let fixture = Fixture::new();
    fixture.confirm();
    let mut assertions: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.assertions).unwrap()).unwrap();
    assertions["cases"][0]["response"]
        .as_object_mut()
        .unwrap()
        .remove("actual_response");
    write(&fixture.paths.assertions, assertions);
    let plan = fixture.plan().unwrap();
    assert_eq!(plan.traffic_e2e_report["status"], "planned_needs_replay");
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["source_validations"],
        1
    );
    assert_eq!(
        plan.traffic_e2e_report["preflight"]["independent_target_validations"],
        0
    );
    assert_eq!(plan.traffic_e2e_report["verified"], false);
    apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}

#[test]
fn changed_policy_is_never_overwritten_and_recovery_retains_source_proof() {
    let fixture = Fixture::new();
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    assert!(recover_rewrite_rule_plan(fixture.context(), &plan.plan_id).is_err());
    let current = format!(
        "{}# another API's reviewed edit\n",
        fs::read_to_string(fixture.policy()).unwrap()
    );
    fs::write(fixture.policy(), &current).unwrap();
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
    assert_eq!(fs::read_to_string(fixture.policy()).unwrap(), current);
    let active = fixture
        .paths
        .replay
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".active");
    fs::create_dir(&active).unwrap();
    assert!(recover_rewrite_rule_plan(fixture.context(), &plan.plan_id).is_err());
    assert!(fixture.state().rule_plan.is_some());
    fs::remove_dir(active).unwrap();
    let recovered = recover_rewrite_rule_plan(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        recovered["retired_plan"]["unified"]["rule_ids"][0],
        "members"
    );
    assert!(
        recovered["retired_plan"]["unified"]["updated"]
            .as_str()
            .unwrap()
            .contains("src/members.rs:12")
    );
    assert_eq!(fs::read_to_string(fixture.policy()).unwrap(), current);
    assert!(fixture.state().rule_plan.is_none() && fixture.state().rule_replay_pending);
}

#[test]
fn a_persisted_apply_intent_rolls_back_on_save_failure_and_retries_after_crash() {
    let fixture = Fixture::new();
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let original = fs::read(fixture.policy()).unwrap();
    let state = fixture.state();
    // Force only the final state publication to fail. The prior revision can
    // still durably journal the intent, and the public apply writes the policy.
    let collision = crate::internal_runtime::root(fixture.root())
        .join("rewrite")
        .join(format!(
            ".state.json.tmp.{}.{}",
            std::process::id(),
            state.revision + 1
        ));
    fs::write(&collision, "reserved by the filesystem-failure test").unwrap();
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
    assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    let journal = fixture.state();
    let record = journal
        .rule_plan
        .as_ref()
        .unwrap()
        .unified
        .as_ref()
        .unwrap();
    assert!(record.apply_started && journal.rule_replay_pending && !journal.e2e_current);
    // Reproduce the exact policy bytes left if termination happened after the
    // authorized write and before final coordinator publication.
    fs::write(fixture.policy(), &record.updated).unwrap();
    fs::remove_file(collision).unwrap();
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    assert!(fixture.state().rule_plan.is_none());
    assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
}

#[test]
fn planning_and_recovery_require_the_current_worker_dispatch() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let query = evidence::commands(fixture.root(), &state)
        .into_iter()
        .find(|q| q.query_id.ends_with("unified-rule-candidates"))
        .unwrap();
    let evidence_id = evidence::query(fixture.root(), &state, &query.query_id)
        .unwrap()
        .evidence_id;
    let error = plan_rewrite_unified_rule(
        fixture.context(),
        RewriteUnifiedRulePlanOptions {
            file: fixture.proposal.clone(),
            evidence_id,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("confirmed dedicated subagent"));
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let mut state = fixture.state();
    state.active_issue.as_mut().unwrap().id = "new-dispatch".into();
    fixture.store().save(&state).unwrap();
    let error = recover_rewrite_rule_plan(fixture.context(), &plan.plan_id).unwrap_err();
    assert!(error.to_string().contains("confirmed dedicated subagent"));
    assert!(fixture.state().rule_plan.is_some());
}

#[test]
fn changed_target_cannot_authorize_a_plan_using_an_old_attempt() {
    let fixture = Fixture::new();
    fixture.confirm();
    fs::write(
        fixture.root().join("lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    let error = fixture.plan().unwrap_err();
    assert!(
        error.to_string().contains("changed since genuine Replay"),
        "{error:#}"
    );
    assert!(fixture.state().rule_plan.is_none());
}
