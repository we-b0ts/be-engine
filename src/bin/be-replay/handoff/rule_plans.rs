//! Bind reviewed Session rules to assignments and verify applied candidate policy.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{
    config::{
        api_catalog::{self, ApiCatalog},
        resolve_unified_policy_path,
    },
    policy::Proof,
    policy_evidence::digest,
};
use traffic_rewrite_rules::rewrite::unified_rule::session as rules;
use uuid::Uuid;

const PROJECT_PATH: &str = ".traffic-e2e/project.yaml";

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct RulePlans(Vec<RulePlan>);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RulePlan {
    id: String,
    plan: RulePlanContent,
    #[serde(default)]
    state: PlanState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlanState {
    #[default]
    Pending,
    Integrated,
    Retired,
}

#[derive(Debug, Serialize, Deserialize)]
struct RulePlanContent {
    request: RuleRequest,
    recording_identity: String,
    attempt_id: Uuid,
    base_commit: String,
    policy_path: PathBuf,
    base_policy_sha256: String,
    proposed_policy_sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RuleRequest {
    pub group: String,
    pub assignment_id: Uuid,
    pub sequences: BTreeSet<u64>,
    pub proposal: String,
    pub source_evidence: Proof,
    pub checks: Vec<String>,
}

pub(crate) struct IntegrationPolicy {
    pub path: PathBuf,
    pub baseline: String,
    pub rendered: String,
}

impl RulePlan {
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn sequences(&self) -> &BTreeSet<u64> {
        &self.plan.request.sequences
    }

    pub(super) fn group(&self) -> &str {
        &self.plan.request.group
    }

    pub(crate) fn prepare(
        root: &Path,
        recording_identity: &str,
        attempt_id: Uuid,
        base_commit: &str,
        request: RuleRequest,
    ) -> Result<Self> {
        super::validate_checks(&request.checks)?;
        let catalog = ApiCatalog::load(&root.join(api_catalog::PATH))?.unwrap_or_default();
        let patterns = catalog.case_paths();
        let path = policy_path(root)?;
        let baseline = committed_policy(root, base_commit, &path)?;
        let proof = &request.source_evidence;
        let mut documented_proof = serde_yaml::to_value(json!({"proof":proof}))?;
        traffic_e2e::policy::require_source_proof(&mut documented_proof, None)
            .context("rule plan requires a Source file/symbol and supporting fact")?;
        let rendered = rules::preview(&baseline, &request.proposal, |api| {
            let Some((_, path)) = api.split_once(' ') else {
                return false;
            };
            let pattern = api_catalog::matching_case_pattern(&patterns, path).unwrap_or(path);
            catalog.routes().get(pattern) == Some(&request.group)
        })?;
        let plan = RulePlanContent {
            request,
            recording_identity: recording_identity.to_owned(),
            attempt_id,
            base_commit: base_commit.to_owned(),
            policy_path: path,
            base_policy_sha256: digest(baseline.as_bytes()),
            proposed_policy_sha256: digest(rendered.as_bytes()),
        };
        Ok(Self {
            id: digest(&serde_json::to_vec(&plan)?),
            plan,
            state: PlanState::Pending,
        })
    }

    pub(crate) fn output(&self) -> Value {
        let mut value = self.summary();
        value["proposal"] = json!(self.plan.request.proposal);
        value["source_evidence"] = json!(self.plan.request.source_evidence);
        value["checks"] = json!(self.plan.request.checks);
        value
    }

    fn summary(&self) -> Value {
        json!({
            "id": self.id,
            "state": self.state,
            "group": self.plan.request.group,
            "assignment_id": self.plan.request.assignment_id.simple().to_string(),
            "attempt_id": self.plan.attempt_id.simple().to_string(),
            "sequence_count": self.plan.request.sequences.len(),
            "base_commit": self.plan.base_commit,
            "policy_path": self.plan.policy_path,
            "base_policy_sha256": self.plan.base_policy_sha256,
            "proposed_policy_sha256": self.plan.proposed_policy_sha256
        })
    }

    fn verify(&self, root: &Path, policy_path: &Path, current: &str) -> Result<()> {
        ensure!(
            self.plan.policy_path == policy_path,
            "rule plan policy path changed"
        );
        ensure!(
            self.id == digest(&serde_json::to_vec(&self.plan)?),
            "rule plan {} has changed",
            self.id
        );
        let baseline = committed_policy(root, &self.plan.base_commit, policy_path)?;
        ensure!(
            self.plan.base_policy_sha256 == digest(baseline.as_bytes()),
            "rule plan {} has a stale assignment baseline",
            self.id
        );
        let preview = rules::preview(&baseline, &self.plan.request.proposal, |_| true)?;
        ensure!(
            self.plan.proposed_policy_sha256 == digest(preview.as_bytes()),
            "rule plan {} has a stale policy preview",
            self.id
        );
        rules::verify_rebase(&baseline, &preview, current)
            .with_context(|| format!("rule plan {} has a stale policy scope", self.id))
    }
}

impl RulePlans {
    pub(super) fn integrated_sequences<'a>(
        &'a self,
        ids: &'a BTreeSet<String>,
    ) -> impl Iterator<Item = u64> + 'a {
        self.0
            .iter()
            .filter(|plan| plan.state == PlanState::Integrated && ids.contains(&plan.id))
            .flat_map(|plan| plan.sequences().iter().copied())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn pending(&self) -> impl Iterator<Item = &RulePlan> {
        self.0
            .iter()
            .filter(|plan| plan.state == PlanState::Pending)
    }

    pub(super) fn retire_pending(&mut self) {
        for plan in &mut self.0 {
            if plan.state == PlanState::Pending {
                plan.state = PlanState::Retired;
            }
        }
    }

    pub(super) fn retire_incompatible(&mut self, root: &Path, target_base: &str) -> Result<()> {
        if self.pending().next().is_none() {
            return Ok(());
        }
        let path = policy_path(root)?;
        let baseline = committed_policy(root, target_base, &path)?;
        for plan in &mut self.0 {
            if plan.state == PlanState::Pending
                && (plan.verify(root, &path, &baseline).is_err()
                    || (plan.plan.base_policy_sha256 != digest(baseline.as_bytes())
                        && rules::preview(&baseline, &plan.plan.request.proposal, |_| true)
                            .is_err()))
            {
                plan.state = PlanState::Retired;
            }
        }
        Ok(())
    }

    pub(super) fn find(&self, attempt: Uuid, request: &RuleRequest) -> Option<&RulePlan> {
        self.0
            .iter()
            .find(|plan| plan.plan.attempt_id == attempt && plan.plan.request == *request)
    }

    pub(super) fn add(&mut self, plan: RulePlan) -> Result<()> {
        ensure!(
            !self.pending().any(|old| {
                old.plan.request.group == plan.plan.request.group
                    && !old
                        .plan
                        .request
                        .sequences
                        .is_disjoint(&plan.plan.request.sequences)
                    && old.plan.request.proposal == plan.plan.request.proposal
            }),
            "an equivalent rule plan already covers some of these sequences"
        );
        self.0.push(plan);
        Ok(())
    }

    pub(super) fn summaries(&self) -> Vec<Value> {
        self.pending().map(RulePlan::summary).collect()
    }

    pub(super) fn covers(&self, group: &str, seq: u64) -> bool {
        self.pending().any(|plan| {
            plan.plan.request.group == group && plan.plan.request.sequences.contains(&seq)
        })
    }

    pub(super) fn render(
        &self,
        root: &Path,
        target_base: &str,
        ids: &BTreeSet<String>,
    ) -> Result<IntegrationPolicy> {
        let path = policy_path(root)?;
        let baseline = committed_policy(root, target_base, &path)?;
        let selected: Vec<_> = self
            .pending()
            .filter(|plan| ids.contains(&plan.id))
            .collect();
        ensure!(
            selected.len() == ids.len(),
            "unknown or already integrated rule plan"
        );
        for plan in &selected {
            plan.verify(root, &path, &baseline)?;
        }
        let rendered = rules::assemble(
            &baseline,
            selected
                .iter()
                .map(|plan| plan.plan.request.proposal.as_str()),
        )?;
        Ok(IntegrationPolicy {
            path,
            baseline,
            rendered,
        })
    }

    pub(super) fn mark_integrated(
        &mut self,
        ids: &BTreeSet<String>,
    ) -> Vec<(String, BTreeSet<u64>)> {
        self.0
            .iter_mut()
            .filter_map(|plan| {
                if plan.state == PlanState::Pending && ids.contains(&plan.id) {
                    plan.state = PlanState::Integrated;
                    Some((
                        plan.plan.request.group.clone(),
                        plan.plan.request.sequences.clone(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl super::Workflow {
    pub(crate) fn ready_rule_covers(&self, group: &str, seq: u64) -> bool {
        self.rule_plans.covers(group, seq)
    }

    pub(crate) fn existing_rule_plan(
        &self,
        attempt: Uuid,
        request: &RuleRequest,
    ) -> Option<&RulePlan> {
        self.rule_plans.find(attempt, request)
    }

    pub(crate) fn add_rule_plan(&mut self, root: &Path, head: &str, plan: RulePlan) -> Result<()> {
        let current = committed_policy(root, head, &plan.plan.policy_path)?;
        plan.verify(root, &plan.plan.policy_path, &current)?;
        rules::preview(&current, &plan.plan.request.proposal, |_| true)
            .context("rule proposal must add a compatible effect to the current Target policy")?;
        rules::assemble(
            &current,
            self.rule_plans
                .pending()
                .chain(std::iter::once(&plan))
                .map(|plan| plan.plan.request.proposal.as_str()),
        )
        .context("rule proposal conflicts with a pending plan")?;
        self.rule_plans.add(plan)
    }

    pub(crate) fn render_rule_plans(
        &self,
        root: &Path,
        target_base: &str,
        ids: &BTreeSet<String>,
    ) -> Result<IntegrationPolicy> {
        self.rule_plans.render(root, target_base, ids)
    }
}

pub(crate) fn policy_path(root: &Path) -> Result<PathBuf> {
    Ok(resolve_unified_policy_path(&root.join(PROJECT_PATH))?
        .strip_prefix(root)?
        .to_owned())
}

pub(crate) fn committed_policy(root: &Path, commit: &str, path: &Path) -> Result<String> {
    #[derive(Deserialize)]
    struct ProjectConfig {
        project: Project,
    }
    #[derive(Deserialize)]
    struct Project {
        policy: PathBuf,
    }

    let config: ProjectConfig =
        serde_yaml::from_str(&git_blob(root, commit, Path::new(PROJECT_PATH))?)?;
    let committed: PathBuf = config
        .project
        .policy
        .components()
        .filter(|part| *part != std::path::Component::CurDir)
        .collect();
    ensure!(
        committed == path,
        "committed replay policy path changed at {commit}"
    );
    git_blob(root, commit, path)
}

fn git_blob(root: &Path, commit: &str, path: &Path) -> Result<String> {
    ensure!(
        crate::round::is_full_commit_id(commit),
        "policy requires a full commit ID"
    );
    let mode = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["--literal-pathspecs", "ls-tree", "-z", commit, "--"])
        .arg(path)
        .output()
        .context("inspect committed Replay policy input")?;
    ensure!(
        mode.status.success() && mode.stdout.starts_with(b"100"),
        "{} must be a committed regular file",
        path.display()
    );
    let object = format!(
        "{commit}:{}",
        path.to_str().context("policy path is not UTF-8")?
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["show", &object])
        .output()
        .context("read committed Replay policy input")?;
    ensure!(
        output.status.success(),
        "cannot read policy input {}",
        path.display()
    );
    String::from_utf8(output.stdout).context("policy input is not UTF-8")
}
