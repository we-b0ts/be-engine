//! Evidence-gated planning for future MySQL process-owned recordings.
use super::{
    background_feedback::plan_rule_config,
    edit::write_atomic,
    process_owned_dependencies::{self, BackgroundDependencyRuleConfig, MysqlBackgroundSelector},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct MysqlBackgroundDependencyFeedback {
    pub rules_path: PathBuf,
    pub replay_report_path: PathBuf,
    pub name: String,
    pub selector: MysqlBackgroundSelector,
    pub source_revision: String,
    pub source_evidence: String,
}

#[derive(Debug, Serialize)]
pub struct MysqlBackgroundDependencyReport {
    pub name: String,
    pub effective_name: String,
    pub selector: MysqlBackgroundSelector,
    pub matched_unused_exchanges: usize,
    pub matched_case_ids: Vec<String>,
    pub changed: bool,
    pub applied: bool,
    pub requires_new_recording: bool,
    pub diff: String,
}

pub struct MysqlBackgroundDependencyPlan {
    feedback: MysqlBackgroundDependencyFeedback,
    snapshots: Vec<(PathBuf, String)>,
    updated_rules: String,
    report: MysqlBackgroundDependencyReport,
}

impl MysqlBackgroundDependencyPlan {
    pub fn report(&self) -> &MysqlBackgroundDependencyReport {
        &self.report
    }
    pub fn apply(self) -> Result<MysqlBackgroundDependencyReport> {
        for (path, raw) in &self.snapshots {
            ensure!(
                read(path)? == *raw,
                "MySQL ownership evidence or rules changed; rerun plan before applying"
            );
        }
        if self.report.changed {
            write_atomic(&self.feedback.rules_path, self.updated_rules.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_mysql_background_dependency(
    feedback: MysqlBackgroundDependencyFeedback,
) -> Result<MysqlBackgroundDependencyPlan> {
    let requested = BackgroundDependencyRuleConfig::Mysql {
        name: feedback.name.clone(),
        selector: feedback.selector.clone(),
        source_revision: feedback.source_revision.clone(),
        source_evidence: feedback.source_evidence.clone(),
    };
    process_owned_dependencies::validate(std::slice::from_ref(&requested))?;
    let raw = read(&feedback.replay_report_path)?;
    let evidence: Value = serde_json::from_str(&raw)?;
    ensure!(
        evidence["version"] == 6 && evidence["finalized"] == true,
        "MySQL ownership planning requires a finalized version-6 replay report"
    );
    for key in ["unmatched_queries", "unsupported_commands"] {
        for event in array(&evidence, key)? {
            if identity_matches(&feedback.selector, event) {
                ensure!(
                    !event["sql"].is_null()
                        && !query_matches(&feedback.selector, event, event["sql"].as_str()),
                    "MySQL selector also matches unmatched or unsupported target traffic"
                );
            }
        }
    }
    let mut snapshots = vec![(feedback.replay_report_path.clone(), raw)];
    let mut dependencies = BTreeMap::<String, Vec<Value>>::new();
    for case in array(&evidence, "cases")? {
        let id = case["case_id"].as_str().context("case has no id")?;
        let recorded_path = PathBuf::from(
            case["dependencies_path"]
                .as_str()
                .context("case has no dependency path")?,
        );
        let path = if recorded_path.is_absolute() {
            recorded_path
        } else {
            feedback
                .replay_report_path
                .parent()
                .unwrap_or(Path::new("."))
                .join(recorded_path)
        };
        let raw = read(&path)?;
        let events = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()?;
        dependencies.insert(id.to_owned(), events);
        snapshots.push((path, raw));
    }
    let mut count = 0;
    let mut cases = BTreeSet::new();
    for unused in array(&evidence, "unused_case_exchanges")? {
        if !identity_matches(&feedback.selector, unused) {
            continue;
        }
        let id = unused["case_id"]
            .as_str()
            .context("unused MySQL exchange has no case")?;
        let events = dependencies
            .get_mut(id)
            .context("unused MySQL exchange has no case evidence")?;
        let expected_fingerprint = unused["sql_summary"]["fingerprint"]
            .as_str()
            .context("unused MySQL exchange has no SQL fingerprint")?;
        let pos = events
            .iter()
            .position(|event| {
                event["event_type"] == "mysql_exchange"
                    && event["command"] == unused["command"]
                    && event["target_host"].as_str().is_some_and(|host| {
                        host.eq_ignore_ascii_case(&feedback.selector.target_host)
                    })
                    && event["target_port"].as_u64()
                        == Some(u64::from(feedback.selector.target_port))
                    && event["database"].as_str() == Some(feedback.selector.database.as_str())
                    && event["username"].as_str() == Some(feedback.selector.username.as_str())
                    && event["sql"]
                        .as_str()
                        .is_some_and(|sql| fingerprint(sql) == expected_fingerprint)
            })
            .context("unused MySQL SQL fingerprint has no corresponding immutable dependency")?;
        let event = events.remove(pos);
        if !query_matches(&feedback.selector, unused, event["sql"].as_str()) {
            continue;
        }
        ensure!(
            event["response"]["status"] == "resultset"
                && event["response"]["rows_truncated"] == false
                && event["parse_warnings"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                && event["response"]["columns"]
                    .as_array()
                    .is_some_and(|c| !c.is_empty())
                && event["response"]["rows"].as_array().is_some_and(|rows| {
                    event["response"]["row_count"].as_u64() == Some(rows.len() as u64)
                        && rows.iter().all(|row| {
                            row.as_array().is_some_and(|row| {
                                row.len() == event["response"]["columns"].as_array().unwrap().len()
                            })
                        })
                }),
            "MySQL ownership evidence is truncated, failed or lacks complete row metadata"
        );
        count += 1;
        cases.insert(id.to_owned());
    }
    ensure!(
        count > 0,
        "MySQL selector matches no replay-safe unused case evidence"
    );
    let plan = plan_rule_config(&feedback.rules_path, requested)?;
    snapshots.push((feedback.rules_path.clone(), plan.original));
    let report = MysqlBackgroundDependencyReport {
        name: feedback.name.clone(),
        effective_name: plan.effective_name,
        selector: feedback.selector.clone(),
        matched_unused_exchanges: count,
        matched_case_ids: cases.into_iter().collect(),
        changed: plan.changed,
        applied: false,
        // A matching unused Case proves this evidence predates classification,
        // even if the same rule has already been applied to configuration.
        requires_new_recording: true,
        diff: plan.diff,
    };
    Ok(MysqlBackgroundDependencyPlan {
        feedback,
        snapshots,
        updated_rules: plan.updated,
        report,
    })
}

fn identity_matches(selector: &MysqlBackgroundSelector, event: &Value) -> bool {
    event["target"]["host"]
        .as_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(&selector.target_host))
        && event["target"]["port"].as_u64() == Some(u64::from(selector.target_port))
        && event["database"].as_str() == Some(selector.database.as_str())
        && event["username"].as_str() == Some(selector.username.as_str())
}
fn query_matches(selector: &MysqlBackgroundSelector, event: &Value, sql: Option<&str>) -> bool {
    selector.matches_query(
        event["target"]["host"].as_str(),
        event["target"]["port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok()),
        event["database"].as_str(),
        event["username"].as_str(),
        event["command"].as_str().unwrap_or_default(),
        sql,
    )
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .with_context(|| format!("replay evidence missing {key}"))
}
fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}
fn fingerprint(sql: &str) -> String {
    let hash = sql.bytes().fold(0xcbf29ce484222325_u64, |hash, b| {
        (hash ^ u64::from(b)).wrapping_mul(0x100000001b3)
    });
    format!("fnv1a64:{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (tempfile::TempDir, MysqlBackgroundDependencyFeedback) {
        let temp = tempfile::tempdir().unwrap();
        let rules = temp.path().join("source-traffic-policy.yaml");
        fs::write(&rules, "version: 2\n").unwrap();
        let deps = temp.path().join("dependencies.jsonl");
        let sql = "SELECT id FROM tasks_0001 WHERE status='RUNNING' AND created_at >= '2026-09-05'";
        let event = json!({"event_type":"mysql_exchange","command":"COM_QUERY","target_host":"db.internal","target_port":3306,"database":"app","username":"user","sql":sql,"parse_warnings":[],"response":{"status":"resultset","columns":[{"name":"id"}],"rows":[],"row_count":0,"rows_truncated":false}});
        fs::write(&deps, event.to_string()).unwrap();
        let replay = temp.path().join("replay.json");
        let target = json!({"host":"db.internal","port":3306});
        fs::write(&replay,json!({"version":6,"finalized":true,"cases":[{"case_id":"case-a","dependencies_path":deps}],"unmatched_queries":[],"unsupported_commands":[],"unused_case_exchanges":[{"case_id":"case-a","command":"COM_QUERY","target":target,"database":"app","username":"user","sql_summary":{"fingerprint":fingerprint(sql)}}]}).to_string()).unwrap();
        let selector = MysqlBackgroundSelector {
            target_host: "db.internal".into(),
            target_port: 3306,
            database: "app".into(),
            username: "user".into(),
            sql: "SELECT id FROM {{table}} WHERE status='RUNNING' AND created_at >= ?".into(),
            tables: vec!["tasks_0001".into()],
            table_series: None,
        };
        (
            temp,
            MysqlBackgroundDependencyFeedback {
                rules_path: rules,
                replay_report_path: replay,
                name: "recovery".into(),
                selector,
                source_revision: "0123456789abcdef".into(),
                source_evidence: "src/recovery.py:run process startup scan".into(),
            },
        )
    }
    #[test]
    fn apply_preserves_evidence_and_requires_new_recording() {
        let (temp, feedback) = fixture();
        let deps = temp.path().join("dependencies.jsonl");
        let before = read(&deps).unwrap();
        let plan = plan_mysql_background_dependency(feedback.clone()).unwrap();
        assert_eq!(plan.report().matched_unused_exchanges, 1);
        assert!(plan.report().requires_new_recording);
        assert!(plan.apply().unwrap().applied);
        assert_eq!(read(&deps).unwrap(), before);
        assert!(
            !plan_mysql_background_dependency(feedback)
                .unwrap()
                .report()
                .changed
        );
    }
    #[test]
    fn rejects_changed_incomplete_or_unmatched_evidence() {
        let (temp, feedback) = fixture();
        let plan = plan_mysql_background_dependency(feedback.clone()).unwrap();
        fs::write(temp.path().join("dependencies.jsonl"), "{}").unwrap();
        assert!(plan.apply().is_err());
        assert!(plan_mysql_background_dependency(feedback).is_err());
        let (_temp, feedback) = fixture();
        let mut report: Value =
            serde_json::from_str(&read(&feedback.replay_report_path).unwrap()).unwrap();
        let mut unmatched = report["unused_case_exchanges"][0].clone();
        unmatched["sql"] =
            json!("SELECT id FROM tasks_0001 WHERE status='RUNNING' AND created_at>=1");
        report["unmatched_queries"] = json!([unmatched]);
        fs::write(&feedback.replay_report_path, report.to_string()).unwrap();
        assert!(plan_mysql_background_dependency(feedback).is_err());
    }
}
