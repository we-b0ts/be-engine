use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::super::config::{load_replay_policy, validate_document};
use super::document::{render_process_output_rules, replace_process_output_rules};

#[derive(Debug, Clone)]
pub struct ProfileTargetMissingFeedback {
    pub project_config_path: PathBuf,
    pub policy_path: PathBuf,
    pub process_output_id: String,
    pub metric: String,
    pub source_revision: String,
    pub dependency_path: Vec<String>,
    pub emitter_evidence: String,
    pub repository_search_evidence: String,
    pub comparison_run: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileTargetMissingReport {
    pub policy: PathBuf,
    pub policy_fingerprint: String,
    pub project_config: PathBuf,
    pub comparison_run: PathBuf,
    pub comparison_evidence_fingerprint: String,
    pub process_output_id: String,
    pub metric: String,
    pub source_revision: String,
    pub dependency_path: Vec<String>,
    pub emitter_evidence: String,
    pub repository_search_evidence: String,
    pub changed: bool,
    pub applied: bool,
    pub diff: String,
}

#[derive(Debug)]
pub struct ProfileTargetMissingPlan {
    policy_path: PathBuf,
    project_config_path: PathBuf,
    original_policy: String,
    original_project_config: String,
    updated_policy: String,
    evidence_paths: Vec<PathBuf>,
    report: ProfileTargetMissingReport,
}

impl ProfileTargetMissingPlan {
    pub fn report(&self) -> &ProfileTargetMissingReport {
        &self.report
    }

    pub fn apply(self) -> Result<ProfileTargetMissingReport> {
        ensure!(
            read_regular_text(&self.policy_path, "verification policy")? == self.original_policy,
            "verification policy changed after planning; rerun plan before applying"
        );
        ensure!(
            read_regular_text(&self.project_config_path, "project config")?
                == self.original_project_config,
            "project config changed after planning; rerun plan before applying"
        );
        ensure!(
            evidence_fingerprint(&self.evidence_paths)?
                == self.report.comparison_evidence_fingerprint,
            "comparison process-output evidence changed after planning; rerun plan before applying"
        );
        if self.report.changed {
            crate::config::edit::write_atomic(&self.policy_path, self.updated_policy.as_bytes())?;
        }
        let mut report = self.report;
        report.applied = true;
        Ok(report)
    }
}

pub fn plan_profile_target_missing(
    feedback: ProfileTargetMissingFeedback,
) -> Result<ProfileTargetMissingPlan> {
    validate_finalized_comparison_run(&feedback.comparison_run)?;
    let original_project_config =
        read_regular_text(&feedback.project_config_path, "project config")?;
    let project = serde_yaml::from_str::<ProjectDocument>(&original_project_config)
        .context("project configuration does not contain valid process_outputs")?;
    let output = project
        .project
        .process_outputs
        .into_iter()
        .find(|output| output.enabled && output.id == feedback.process_output_id)
        .with_context(|| {
            format!(
                "project process_outputs does not contain enabled output {:?}",
                feedback.process_output_id
            )
        })?;
    let config =
        crate::process_output::ProcessOutputConfig::profile_by_type(output.id, output.path);
    let (record_type, name) = split_metric(&feedback.metric)?;
    crate::process_output::validate_profile_target_missing_evidence(
        &config,
        &feedback.comparison_run,
        record_type,
        name,
    )?;
    let metric = crate::process_output::canonical_profile_metric(record_type, name);
    let evidence_paths =
        comparison_evidence_paths(&feedback.comparison_run, &feedback.process_output_id);
    let comparison_evidence_fingerprint = evidence_fingerprint(&evidence_paths)?;

    let original_policy = read_regular_text(&feedback.policy_path, "verification policy")?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let allowance = crate::ProfileTargetMissingAllowance {
        metric: metric.clone(),
        source_revision: feedback.source_revision,
        dependency_path: feedback.dependency_path,
        emitter_evidence: feedback.emitter_evidence,
        repository_search_evidence: feedback.repository_search_evidence,
    };
    let rules = loaded
        .document
        .process_output_rules
        .entry(feedback.process_output_id.clone())
        .or_default();
    let existing = rules.allow_target_missing.iter().find(|existing| {
        existing
            .metric
            .split_once('.')
            .is_some_and(|(existing_type, existing_name)| {
                crate::process_output::canonical_profile_metric(existing_type, existing_name)
                    == metric
            })
    });
    let changed = if let Some(existing) = existing {
        ensure!(
            existing == &allowance,
            "allow_target_missing metric {metric:?} already exists with different evidence"
        );
        false
    } else {
        rules.allow_target_missing.push(allowance.clone());
        true
    };
    validate_document(&loaded.document)?;
    let updated_policy =
        replace_process_output_rules(&original_policy, &loaded.document.process_output_rules)?;
    let diff = if changed {
        format!(
            "--- {0}\n+++ {0}\n@@ process_output_rules @@\n{1}",
            feedback.policy_path.display(),
            render_process_output_rules(&loaded.document.process_output_rules)?
        )
    } else {
        String::new()
    };
    Ok(ProfileTargetMissingPlan {
        policy_path: feedback.policy_path.clone(),
        project_config_path: feedback.project_config_path.clone(),
        original_policy,
        original_project_config,
        updated_policy,
        evidence_paths,
        report: ProfileTargetMissingReport {
            policy: feedback.policy_path,
            policy_fingerprint: loaded.fingerprint,
            project_config: feedback.project_config_path,
            comparison_run: feedback.comparison_run,
            comparison_evidence_fingerprint,
            process_output_id: feedback.process_output_id,
            metric,
            source_revision: allowance.source_revision,
            dependency_path: allowance.dependency_path,
            emitter_evidence: allowance.emitter_evidence,
            repository_search_evidence: allowance.repository_search_evidence,
            changed,
            applied: false,
            diff,
        },
    })
}

#[derive(Debug, Deserialize)]
struct ProjectDocument {
    project: ProjectSettingsDocument,
}

#[derive(Debug, Deserialize)]
struct ProjectSettingsDocument {
    #[serde(default)]
    process_outputs: Vec<ProcessOutputSetting>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessOutputSetting {
    id: String,
    path: PathBuf,
    enabled: bool,
}

fn split_metric(metric: &str) -> Result<(&str, &str)> {
    let (record_type, name) = metric
        .split_once('.')
        .context("--metric must use <type>.<name> format")?;
    ensure!(
        !record_type.is_empty() && !name.is_empty(),
        "--metric must use <type>.<name> format"
    );
    Ok((record_type, name))
}

fn comparison_evidence_paths(comparison_run: &Path, output_id: &str) -> Vec<PathBuf> {
    let mut paths = vec![comparison_run.join("comparison-recording-run.json")];
    paths.extend(["source", "target"].into_iter().flat_map(|side| {
        let root = comparison_run
            .join("process-outputs")
            .join(side)
            .join(output_id);
        [
            root.join("manifest.json"),
            root.join(format!("{side}.data")),
        ]
    }));
    paths
}

fn validate_finalized_comparison_run(comparison_run: &Path) -> Result<()> {
    let path = comparison_run.join("comparison-recording-run.json");
    let summary: ComparisonRunSummary =
        serde_json::from_slice(&read_regular(&path, "comparison recording summary")?)
            .with_context(|| format!("invalid comparison recording summary {}", path.display()))?;
    ensure!(
        summary.status == "completed" && summary.finished_at.is_some(),
        "comparison recording run is not finalized successfully"
    );
    ensure!(
        summary.ready,
        "comparison recording run never observed both upstreams ready"
    );
    ensure!(
        summary.counts.published > 0 && summary.counts.failed == 0 && summary.errors.is_empty(),
        "comparison recording run is empty or contains failures"
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ComparisonRunSummary {
    status: String,
    finished_at: Option<serde_json::Value>,
    ready: bool,
    counts: ComparisonRunCounts,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ComparisonRunCounts {
    published: usize,
    failed: usize,
}

fn evidence_fingerprint(paths: &[PathBuf]) -> Result<String> {
    let mut payload = Vec::new();
    for path in paths {
        let bytes = read_regular(path, "comparison process-output evidence")?;
        payload.extend_from_slice(path.to_string_lossy().as_bytes());
        payload.push(0);
        payload.extend_from_slice(&bytes);
        payload.push(0xff);
    }
    Ok(crate::verification_progress::fingerprint(&payload))
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink: {}",
        path.display()
    );
    fs::read(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn read_regular_text(path: &Path, label: &str) -> Result<String> {
    String::from_utf8(read_regular(path, label)?)
        .with_context(|| format!("{label} is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_output::{ProcessOutputCaptureSide, ProcessOutputConfig};

    #[test]
    fn plans_and_applies_a_canonical_evidence_bound_allowance() {
        let fixture = fixture(
            br#"2026-09-01 {"type":"HTTP","name":"all_http://telemetry.example/ping","slowThreshold":50,"total_count":3}
"#,
            b"",
        );
        let feedback = feedback(&fixture, "HTTP.all_http://telemetry.example/ping");

        let plan = plan_profile_target_missing(feedback).unwrap();

        assert!(plan.report().changed);
        assert!(!plan.report().applied);
        assert_eq!(plan.report().metric, "HTTP.http://telemetry.example/ping");
        assert!(plan.report().diff.contains("allow_target_missing"));
        let report = plan.apply().unwrap();
        assert!(report.applied);
        let policy = fs::read_to_string(&fixture.policy).unwrap();
        assert!(policy.contains("metric: HTTP.http://telemetry.example/ping"));
        let validated = crate::replay::validate_replay_policy(&fixture.policy).unwrap();
        assert_eq!(
            validated.process_output_rules["metrics-profile"].allow_target_missing[0].metric,
            "HTTP.http://telemetry.example/ping"
        );
    }

    #[test]
    fn plan_rejects_unfinalized_or_partially_present_evidence() {
        let fixture = fixture(
            br#"2026-09-01 {"type":"HTTP","name":"all_http://telemetry.example/ping","slowThreshold":50,"total_count":3}
2026-09-01 {"type":"HTTP","name":"http://telemetry.example/ping","slowThreshold":50,"total_count":3}
"#,
            br#"2026-09-01 {"type":"HTTP","name":"http://telemetry.example/ping","slowThreshold":50,"total_count":3}
"#,
        );
        let error = plan_profile_target_missing(feedback(
            &fixture,
            "HTTP.all_http://telemetry.example/ping",
        ))
        .unwrap_err();
        assert!(error.to_string().contains("does not show source-positive"));

        fs::write(
            fixture.run.join("comparison-recording-run.json"),
            br#"{"status":"running","finished_at":null,"ready":true,"counts":{"published":1,"failed":0},"errors":[]}"#,
        )
        .unwrap();
        let error = plan_profile_target_missing(feedback(
            &fixture,
            "HTTP.all_http://telemetry.example/ping",
        ))
        .unwrap_err();
        assert!(error.to_string().contains("not finalized successfully"));
    }

    #[test]
    fn apply_rejects_changes_after_planning() {
        let fixture = fixture(
            br#"2026-09-01 {"type":"RPC_SERVICE_CLIENT_V2","name":"Example.call()","slowThreshold":50,"total_count":3}
"#,
            b"",
        );
        let plan =
            plan_profile_target_missing(feedback(&fixture, "RPC_SERVICE_CLIENT_V2.Example.call()"))
                .unwrap();
        assert_eq!(plan.report().metric, "RPC_SERVICE_CLIENT.Example.call()");
        fs::write(&fixture.project, "changed").unwrap();

        let error = plan.apply().unwrap_err();
        assert!(error.to_string().contains("project config changed"));
    }

    struct Fixture {
        _root: tempfile::TempDir,
        project: PathBuf,
        policy: PathBuf,
        run: PathBuf,
    }

    fn fixture(source: &[u8], target: &[u8]) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project.yaml");
        let policy = root.path().join("verification.yaml");
        let run = root.path().join("comparison-run");
        fs::create_dir_all(&run).unwrap();
        fs::write(
            &project,
            "project:\n  process_outputs:\n  - id: metrics-profile\n    path: /data1/weibo/logs/profile.log\n    enabled: true\n",
        )
        .unwrap();
        fs::write(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        fs::write(
            run.join("comparison-recording-run.json"),
            br#"{"status":"completed","finished_at":"2026-09-03T00:00:00Z","ready":true,"counts":{"published":1,"failed":0},"errors":[]}"#,
        )
        .unwrap();
        let config = ProcessOutputConfig::profile_by_type(
            "metrics-profile".to_string(),
            PathBuf::from("/data1/weibo/logs/profile.log"),
        );
        let captures = run.join("process-outputs");
        crate::process_output::write_test_capture(
            &captures.join("source"),
            &config,
            ProcessOutputCaptureSide::Source,
            Some(source),
        )
        .unwrap();
        crate::process_output::write_test_capture(
            &captures.join("target"),
            &config,
            ProcessOutputCaptureSide::Target,
            Some(target),
        )
        .unwrap();
        Fixture {
            _root: root,
            project,
            policy,
            run,
        }
    }

    fn feedback(fixture: &Fixture, metric: &str) -> ProfileTargetMissingFeedback {
        ProfileTargetMissingFeedback {
            project_config_path: fixture.project.clone(),
            policy_path: fixture.policy.clone(),
            process_output_id: "metrics-profile".to_string(),
            metric: metric.to_string(),
            source_revision: "0123456789abcdef".to_string(),
            dependency_path: vec![
                "com.example:client:1.0.0".to_string(),
                "com.vendor:telemetry:2.0.0".to_string(),
            ],
            emitter_evidence: "TelemetryInitializer#start emits the interaction".to_string(),
            repository_search_evidence: "No direct endpoint call, client construction, bean, initializer, or startup registration at source revision"
                .to_string(),
            comparison_run: fixture.run.clone(),
        }
    }
}
