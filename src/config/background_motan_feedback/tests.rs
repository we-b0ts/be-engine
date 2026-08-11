use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;
use crate::config::{AppConfig, BackgroundDependencyRuleConfig};

const INTERFACE: &str = "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc";
const METHOD: &str = "getConfigByName";
const GROUP: &str = "kunpeng-config-rpc";
const REVISION: &str = "0123456789abcdef";
const EVIDENCE: &str = "MapiConfigLoader.java:init scheduled refresh unrelated to selected API";

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    replay_report: PathBuf,
}

impl Fixture {
    fn new(report: Value) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("recorder.toml");
        let replay_report = temp.path().join("replay-report.json");
        fs::write(&config, "[recording]\ntraffic_jsonl = \"full\"\n").unwrap();
        fs::write(&replay_report, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        Self {
            _temp: temp,
            config,
            replay_report,
        }
    }

    fn feedback(&self) -> MotanBackgroundDependencyFeedback {
        MotanBackgroundDependencyFeedback {
            config_path: self.config.clone(),
            replay_report_path: self.replay_report.clone(),
            name: "kunpeng-refresh".to_string(),
            group: GROUP.to_string(),
            interface_name: INTERFACE.to_string(),
            method_name: METHOD.to_string(),
            source_revision: REVISION.to_string(),
            source_evidence: EVIDENCE.to_string(),
        }
    }
}

fn command(command: &str, case_id: Option<&str>) -> Value {
    json!({
        "case_id": case_id,
        "target": {
            "host": "vintage-node-10-145-1-1.trp.test",
            "port": 8882,
        },
        "command": command,
    })
}

fn report_with_unused() -> Value {
    json!({
        "version": 6,
        "finalized": true,
        "motan": {
            "unmatched": [],
            "unsupported": [],
            "unsafe_events": [],
            "unused_case": [
                command(&format!("{INTERFACE}#{METHOD}"), Some("case-b")),
                command(&format!("{INTERFACE}#{METHOD}"), Some("case-a")),
            ],
        },
    })
}

#[test]
fn plan_and_apply_add_an_idempotent_motan_rule_without_endpoint_identity() {
    let fixture = Fixture::new(report_with_unused());

    let plan = plan_motan_background_dependency(fixture.feedback()).unwrap();
    assert!(plan.report().changed);
    assert!(!plan.report().applied);
    assert_eq!(plan.report().matched_unused_exchanges, 2);
    assert_eq!(plan.report().matched_case_ids, ["case-a", "case-b"]);
    assert_eq!(plan.report().group, GROUP);
    assert_eq!(plan.report().interface_name, INTERFACE);
    assert_eq!(plan.report().method_name, METHOD);
    assert!(plan.apply().unwrap().applied);

    let raw = fs::read_to_string(&fixture.config).unwrap();
    assert!(raw.contains("protocol = \"motan\""));
    assert!(raw.contains(&format!("group = \"{GROUP}\"")));
    assert!(raw.contains(&format!("interface_name = \"{INTERFACE}\"")));
    assert!(raw.contains(&format!("method_name = \"{METHOD}\"")));
    assert!(!raw.contains("vintage-node-"));
    assert!(!raw.contains("response_role"));

    let config = AppConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &config.recording.process_owned_dependencies[0],
        BackgroundDependencyRuleConfig::Motan {
            group,
            interface_name,
            method_name,
            ..
        } if group == GROUP && interface_name == INTERFACE && method_name == METHOD
    ));

    let repeated = plan_motan_background_dependency(fixture.feedback()).unwrap();
    assert!(!repeated.report().changed);
    assert!(repeated.report().diff.is_empty());
}

#[test]
fn rejects_incomplete_missing_or_conflicting_evidence() {
    let mut report = report_with_unused();
    report["finalized"] = json!(false);
    let fixture = Fixture::new(report);
    assert!(
        plan_motan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("finalized")
    );

    let mut report = report_with_unused();
    report["motan"]["unused_case"] = json!([]);
    let fixture = Fixture::new(report);
    assert!(
        plan_motan_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("matches no unused")
    );

    for field in ["unmatched", "unsupported", "unsafe_events"] {
        let mut report = report_with_unused();
        report["motan"][field] = json!([command(&format!("{INTERFACE}#{METHOD}"), Some("case-a"))]);
        let fixture = Fixture::new(report);
        assert!(
            plan_motan_background_dependency(fixture.feedback())
                .unwrap_err()
                .to_string()
                .contains("unsafe target traffic")
        );
    }
}

#[test]
fn apply_rejects_stale_config_or_replay_report() {
    let fixture = Fixture::new(report_with_unused());
    let plan = plan_motan_background_dependency(fixture.feedback()).unwrap();
    fs::write(&fixture.config, "[recording]\ntraffic_jsonl = \"off\"\n").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("config changed")
    );

    let fixture = Fixture::new(report_with_unused());
    let plan = plan_motan_background_dependency(fixture.feedback()).unwrap();
    let mut report = report_with_unused();
    report["selected_case_ids"] = json!(["case-a"]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("replay report changed")
    );
}

#[test]
fn existing_name_cannot_change_its_selector() {
    let fixture = Fixture::new(report_with_unused());
    plan_motan_background_dependency(fixture.feedback())
        .unwrap()
        .apply()
        .unwrap();

    let mut report = report_with_unused();
    report["motan"]["unused_case"] = json!([command(
        &format!("{INTERFACE}#getOtherConfig"),
        Some("case-a")
    )]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    let mut feedback = fixture.feedback();
    feedback.method_name = "getOtherConfig".to_string();
    assert!(
        plan_motan_background_dependency(feedback)
            .unwrap_err()
            .to_string()
            .contains("different selector")
    );
}
