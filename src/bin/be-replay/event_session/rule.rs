//! Session rule authoring and policy application in a registered integration task.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command as Git,
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde::Deserialize;
use serde_json::json;
use traffic_e2e::{E2eEventSessionState, policy::Proof, policy_evidence::digest, repository};
use uuid::Uuid;

use crate::{
    handoff::{
        AssignmentDetail, Registration, read_sequence_file,
        rule_plans::{self, RulePlan, RuleRequest},
    },
    print_json,
    round::Repository,
};

use super::{status, workflow};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Register a policy proposal for an active implementation assignment.
    Plan {
        /// JSON proposal with references to a sequence file and a policy fragment.
        #[arg(long)]
        file: PathBuf,
    },
    /// Apply the selected plans in the registered integrator's linked worktree.
    Apply(Apply),
}

#[derive(Debug, Args)]
pub(crate) struct Apply {
    #[arg(long)]
    worktree: PathBuf,
    #[arg(long)]
    task_id: String,
    #[arg(long)]
    agent_handle: String,
    /// Repeat for each selected rule plan.
    #[arg(long, required = true, num_args = 1..)]
    plan_id: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    group: String,
    assignment_id: Uuid,
    sequences_file: PathBuf,
    proposal_file: PathBuf,
    source_evidence: Proof,
    checks: Vec<String>,
}

pub(super) fn run(
    root: &Path,
    recording: Option<&str>,
    command: Command,
    pretty: bool,
) -> Result<()> {
    match command {
        Command::Plan { file } => register(root, recording, &file, pretty),
        Command::Apply(args) => apply(root, recording, args, pretty),
    }
}

fn register(root: &Path, id: Option<&str>, file: &Path, pretty: bool) -> Result<()> {
    let submission: Submission =
        serde_json::from_reader(File::open(file)?).context("parse Session rule plan request")?;
    let directory = file
        .parent()
        .context("plan request must have a parent directory")?;
    let request = RuleRequest {
        group: submission.group,
        assignment_id: submission.assignment_id,
        sequences: read_sequence_file(&directory.join(submission.sequences_file))?,
        proposal: read_proposal(&directory.join(submission.proposal_file))?,
        source_evidence: submission.source_evidence,
        checks: submission.checks,
    };
    let repo = Repository::load(root)?;
    let lock = repo.lock_round_for_update()?;
    repo.check_checkout(&lock)?;
    ensure!(
        status::configuration_action(&repo.root)?.is_none(),
        "commit the Replay configuration before registering a rule plan"
    );
    let mut round = workflow::require_round(&repo)?;
    let recording = workflow::round_recording(&repo, &round, id)?;
    let current = workflow::current_attempt(&repo, &round, &recording)?;
    ensure!(
        current.state == E2eEventSessionState::Failed,
        "register a rule plan for the current failed Replay attempt"
    );
    let attempt = current
        .attempt
        .as_ref()
        .context("rule plan requires a Replay attempt")?;
    let attempt_id = attempt.attempt_id.parse()?;
    if let Some(existing) = round.workflow.existing_rule_plan(attempt_id, &request) {
        return print_json(
            &json!({"recording_id": recording.id, "rule_plan": existing.output()}),
            pretty,
        );
    }
    let base = round.workflow.validate_delivery_sequences(
        &request.group,
        request.assignment_id,
        &request.sequences,
    )?;
    let plan = RulePlan::prepare(&repo.root, &recording.identity, attempt_id, base, request)?;
    let output = plan.output();
    round.workflow.add_rule_plan(&repo.root, &repo.head, plan)?;
    repo.save_round(&lock, round)?;
    print_json(
        &json!({"recording_id": recording.id, "rule_plan": output}),
        pretty,
    )
}

fn apply(root: &Path, id: Option<&str>, args: Apply, pretty: bool) -> Result<()> {
    let repo = Repository::load(root)?;
    let lock = repo.lock_round_for_update()?;
    repo.check_checkout(&lock)?;
    ensure!(
        status::configuration_action(&repo.root)?.is_none(),
        "commit the Replay configuration before applying Session rules"
    );
    let round = workflow::require_round(&repo)?;
    let recording = workflow::round_recording(&repo, &round, id)?;
    let current = workflow::current_attempt(&repo, &round, &recording)?;
    let attempt = current
        .attempt
        .as_ref()
        .context("policy application requires a Replay attempt")?;
    let action = status::attempt_action(
        &repo,
        &round,
        current.state,
        Some(attempt),
        AssignmentDetail::Summary,
    )?;
    ensure!(
        action.output["details"]["task"]["requirement"] == "integration_required",
        "rule application requires the current integration task"
    );
    let task = action
        .task
        .context("the current integration task is missing")?;
    round.workflow.require_task_delivery(
        &task,
        &Registration {
            task_id: args.task_id,
            agent_handle: args.agent_handle,
        },
    )?;
    let plans = args.plan_id.into_iter().collect::<BTreeSet<_>>();
    let base = attempt
        .target_commit
        .as_deref()
        .context("attempt lacks a Target commit")?;
    let policy = round.workflow.render_rule_plans(&repo.root, base, &plans)?;
    ensure!(
        rule_plans::committed_policy(&repo.root, &repo.head, &policy.path)? == policy.baseline,
        "canonical policy changed after Replay; revalidate before applying rules"
    );
    let worktree = integration_worktree(&repo, &args.worktree)?;
    let head = git_output(&worktree, &["rev-parse", "--verify", "HEAD"])?;
    let committed = rule_plans::committed_policy(&worktree, &head, &policy.path)?;
    ensure!(
        committed == policy.baseline || committed == policy.rendered,
        "integration policy has edits outside the selected plans"
    );
    ensure!(
        rule_plans::policy_path(&worktree)? == policy.path,
        "integration worktree changed project.policy"
    );
    let changed = write_policy(
        &worktree.join(&policy.path),
        &policy.baseline,
        &policy.rendered,
    )?;
    print_json(
        &json!({
            "recording_id": recording.id,
            "policy_path": policy.path,
            "policy_sha256": digest(policy.rendered.as_bytes()),
            "included_rule_plans": plans,
            "changed": changed
        }),
        pretty,
    )
}

fn read_proposal(path: &Path) -> Result<String> {
    const LIMIT: u64 = 1024 * 1024;
    let mut input = String::new();
    File::open(path)?
        .take(LIMIT + 1)
        .read_to_string(&mut input)?;
    ensure!(input.len() as u64 <= LIMIT, "policy proposal exceeds 1 MiB");
    Ok(input)
}

fn integration_worktree(repo: &Repository, path: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(path).context("resolve integration worktree")?;
    let slot = repository::implementer_worktree(&repo.root, 0);
    let implementer = root.parent() == slot.parent()
        && root
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"api-implementer-"));
    ensure!(
        root != repo.root && !implementer && repository::git_root(&root)? == root,
        "use a separate linked integration worktree"
    );
    let common_dir = ["rev-parse", "--path-format=absolute", "--git-common-dir"];
    ensure!(
        git_output(&root, &common_dir)? == git_output(&repo.root, &common_dir)?,
        "integration worktree must belong to the canonical Target"
    );
    ensure!(
        Git::new("git")
            .arg("-C")
            .arg(&root)
            .args(["merge-base", "--is-ancestor", &repo.head, "HEAD"])
            .status()?
            .success(),
        "integration worktree must contain the canonical Target commit"
    );
    Ok(root)
}

fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    let output = Git::new("git").arg("-C").arg(root).args(args).output()?;
    ensure!(
        output.status.success(),
        "cannot inspect integration worktree Git identity"
    );
    Ok(String::from_utf8(output.stdout)?.trim_end().to_owned())
}

fn write_policy(path: &Path, baseline: &str, rendered: &str) -> Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "integration policy must be a regular file"
    );
    let original = fs::read_to_string(path)?;
    if original == rendered {
        return Ok(false);
    }
    ensure!(
        original == baseline,
        "integration policy has uncommitted changes outside the selected plans"
    );
    let directory = path
        .parent()
        .context("integration policy requires a parent directory")?;
    let temporary = directory.join(format!(".session-policy-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        temp.write_all(rendered.as_bytes())?;
        temp.set_permissions(metadata.permissions())?;
        temp.sync_all()?;
        ensure!(
            fs::read_to_string(path)? == original,
            "integration policy changed during apply"
        );
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.context("apply Session rule policy")?;
    Ok(true)
}
