//! Source regression rounds and the active recording for a Target branch.
mod git;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use traffic_e2e::{
    E2eEventSessionState,
    config::project::config::{PROJECT_CONFIG_FILE, load_project_config},
    dependency_index::recording,
    internal_runtime, policy_evidence,
    repository::{LOCAL_ARTIFACTS_ROOT, TRAFFIC_E2E_ROOT},
    status_e2e_event_session,
};
use uuid::Uuid;

use super::handoff::Workflow;

#[derive(Debug)]
pub(super) struct Repository {
    pub root: PathBuf,
    pub branch: Option<String>,
    pub pr_base: String,
    pub head: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Round {
    pub branch: String,
    pub pr_base: String,
    pub base_commit: String,
    pub recording_id: String,
    pub recording_identity: String,
    pub run_key: String,
    pub workflow: Workflow,
}

#[derive(Debug, Deserialize, Serialize)]
struct BranchRounds {
    #[serde(flatten)]
    active: Round,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    inactive: BTreeMap<String, Round>,
}

#[derive(Debug)]
pub(super) struct Recording {
    pub id: String,
    pub root: PathBuf,
    pub identity: String,
}

pub(super) struct RoundLock {
    file: File,
    repository: PathBuf,
}

impl Drop for RoundLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl Repository {
    pub fn load(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root).context("resolve Target repository")?;
        let config = load_project_config(
            &root,
            &root.join(TRAFFIC_E2E_ROOT).join(PROJECT_CONFIG_FILE),
        )?;
        let (branch, head) = git::checkout(&root)?;
        Ok(Self {
            root,
            branch,
            pr_base: config.project.delivery.pr_base,
            head,
        })
    }

    pub fn on_base(&self) -> bool {
        self.branch.as_deref() == Some(&self.pr_base)
    }

    pub fn read_round(&self) -> Result<Option<Round>> {
        Ok(self.branch_rounds()?.map(|rounds| rounds.active))
    }

    pub fn inspect_round(&self, id: Option<&str>) -> Result<(Option<Round>, bool)> {
        let Some(mut rounds) = self.branch_rounds()? else {
            return Ok((None, false));
        };
        if let Some(id) = id.filter(|&id| id != rounds.active.recording_id) {
            Ok((rounds.inactive.remove(id), true))
        } else {
            Ok((Some(rounds.active), false))
        }
    }

    fn branch_rounds(&self) -> Result<Option<BranchRounds>> {
        let Some(branch) = self.branch.as_deref().filter(|_| !self.on_base()) else {
            return Ok(None);
        };
        let Some(rounds) = read_rounds(&self.round_path(branch))? else {
            return Ok(None);
        };
        let matches_branch =
            |round: &Round| round.branch == branch && round.pr_base == self.pr_base;
        ensure!(
            matches_branch(&rounds.active)
                && rounds
                    .inactive
                    .iter()
                    .all(|(id, round)| id == &round.recording_id
                        && id != &rounds.active.recording_id
                        && matches_branch(round)),
            "stored round does not match the current branch and configured pr_base"
        );
        Ok(Some(rounds))
    }

    pub fn lock(&self) -> Result<RoundLock> {
        let root = internal_runtime::root(&self.root);
        git::require_ignored(&self.root, &root)?;
        fs::create_dir_all(&root)?;
        let file = open_lock(&root.join("replay-round.lock"))?;
        file.try_lock()
            .context("another be-replay operation is active for this Target")?;
        let lock = RoundLock {
            file,
            repository: self.root.clone(),
        };
        self.check_checkout(&lock)?;
        Ok(lock)
    }

    pub fn check_checkout(&self, lock: &RoundLock) -> Result<()> {
        ensure!(
            lock.repository == self.root,
            "round lock belongs to another Target"
        );
        let (branch, head) = git::checkout(&self.root)?;
        ensure!(
            branch == self.branch && head == self.head,
            "Target checkout changed during be-replay operation; inspect status again"
        );
        Ok(())
    }

    pub fn select_round(
        &mut self,
        lock: &RoundLock,
        recording: Recording,
        user_confirm: bool,
        run_key: Option<String>,
    ) -> Result<Round> {
        self.check_checkout(lock)?;
        let branch = self
            .branch
            .as_deref()
            .context("check out a named Target branch")?;
        let on_base = self.on_base();
        ensure!(
            user_confirm || !on_base,
            "starting a regression on pr_base requires user approval and `run --user-confirm`"
        );
        ensure!(
            !user_confirm || on_base,
            "run --user-confirm applies only on pr_base; resume the current work branch with run"
        );
        let active = open_lock(&internal_runtime::root(&self.root).join("event-replay.lock"))?;
        active
            .try_lock()
            .context("another event Replay is active for this Target")?;
        let branch = if on_base {
            git::next_branch(&self.root, |branch| self.round_path(branch).exists())?
        } else {
            branch.to_string()
        };
        let path = self.round_path(&branch);
        let mut inactive = if let Some(mut current) = self.branch_rounds()? {
            if current.active.recording_id == recording.id {
                current.active.validate_recording(&recording)?;
                current.active.validate_run_key(run_key.as_deref())?;
                return Ok(current.active);
            }
            current
                .inactive
                .insert(current.active.recording_id.clone(), current.active);
            current.inactive
        } else {
            BTreeMap::new()
        };
        let round = if let Some(round) = inactive.remove(&recording.id) {
            round.validate_recording(&recording)?;
            round.validate_run_key(run_key.as_deref())?;
            round
        } else {
            self.new_round(branch, recording, run_key)?
        };
        let rounds = BranchRounds {
            active: round,
            inactive,
        };
        // Publish the binding before switching so an interruption after Git changes HEAD
        // still leaves a resumable round on the new branch.
        self.check_checkout(lock)?;
        persist(&path, &rounds)?;
        let round = rounds.active;
        if on_base {
            self.check_checkout(lock)?;
            if let Err(error) = git::switch(&self.root, &round.branch, &self.head) {
                if git::checkout(&self.root).is_ok_and(|(branch, _)| branch == self.branch) {
                    let _ = fs::remove_file(&path);
                }
                return Err(error)
                    .context("failed to enter the Replay branch; inspect status before retrying");
            }
            self.branch = Some(round.branch.clone());
            self.check_checkout(lock)?;
        }
        Ok(round)
    }

    fn new_round(
        &self,
        branch: String,
        recording: Recording,
        run_key: Option<String>,
    ) -> Result<Round> {
        let run_key = run_key.unwrap_or_else(|| format!("replay-{}", Uuid::new_v4().simple()));
        validate_run_key(&run_key)?;
        ensure!(
            self.run_key_available(&run_key, &recording.id)?,
            "run key {run_key:?} already belongs to another round for this recording"
        );
        ensure!(
            status_e2e_event_session(&self.root, &recording.root, Some(&run_key), None)?.state
                == E2eEventSessionState::NotStarted,
            "run key {run_key:?} already has attempts for this recording"
        );
        Ok(Round {
            branch,
            pr_base: self.pr_base.clone(),
            base_commit: self.head.clone(),
            recording_id: recording.id,
            recording_identity: recording.identity,
            run_key,
            workflow: Workflow::default(),
        })
    }

    pub fn save_round(&self, lock: &RoundLock, round: Round) -> Result<()> {
        self.check_checkout(lock)?;
        ensure!(
            self.branch.as_deref() == Some(&round.branch)
                && !self.on_base()
                && self.pr_base == round.pr_base,
            "cannot update a round from a different branch or pr_base"
        );
        let path = self.round_path(&round.branch);
        let mut rounds = self.branch_rounds()?.context("current round disappeared")?;
        let current = &rounds.active;
        ensure!(
            current.branch == round.branch
                && current.pr_base == round.pr_base
                && current.recording_id == round.recording_id
                && current.recording_identity == round.recording_identity
                && current.base_commit == round.base_commit
                && current.run_key == round.run_key,
            "round identity changed during be-replay operation"
        );
        rounds.active = round;
        persist(&path, &rounds)
    }

    fn rounds_dir(&self) -> PathBuf {
        internal_runtime::root(&self.root).join("replay-rounds")
    }

    fn round_path(&self, branch: &str) -> PathBuf {
        let digest = policy_evidence::digest(branch.as_bytes());
        self.rounds_dir().join(format!("{}.json", &digest[7..]))
    }

    fn run_key_available(&self, run_key: &str, recording_id: &str) -> Result<bool> {
        let Some(entries) = optional_entries(&self.rounds_dir())? else {
            return Ok(true);
        };
        for entry in entries {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
                && let Some(rounds) = read_rounds(&path)?
                && (matches_recording_key(&rounds.active, recording_id, run_key)
                    || rounds
                        .inactive
                        .get(recording_id)
                        .is_some_and(|round| matches_recording_key(round, recording_id, run_key)))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Round {
    pub fn validate_run_key(&self, key: Option<&str>) -> Result<()> {
        ensure!(
            key.is_none_or(|key| key == self.run_key),
            "recording {} already uses run key {} on this branch",
            self.recording_id,
            self.run_key
        );
        Ok(())
    }

    pub fn validate_recording(&self, recording: &Recording) -> Result<()> {
        ensure!(
            recording.id == self.recording_id && recording.identity == self.recording_identity,
            "selected Source recording changed since this round was confirmed"
        );
        Ok(())
    }
}

impl Recording {
    pub fn load(root: &Path, id: &str) -> Result<Self> {
        ensure!(
            valid_recording_id(id),
            "recording run ID must contain 14 digits"
        );
        let path = recording_directory(root).join(id);
        let path = fs::canonicalize(&path)
            .with_context(|| format!("resolve Source recording {}", path.display()))?;
        let (root, manifest) = recording::manifest(&path)?;
        ensure!(
            root == path && manifest.run_id == id,
            "recording manifest does not match the selected run ID"
        );
        ensure!(
            manifest.capture_complete,
            "Source session capture is incomplete"
        );
        ensure!(
            manifest
                .files
                .iter()
                .any(|file| file.path == "events.tsv" && file.length > 0),
            "recording has no sealed Source event stream"
        );
        Ok(Self {
            id: id.to_string(),
            root,
            identity: policy_evidence::digest(&serde_json::to_vec(&manifest)?),
        })
    }
}

pub(super) fn recordings(root: &Path) -> Result<Vec<String>> {
    let Some(entries) = optional_entries(&recording_directory(root))? else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    for entry in entries {
        if let Ok(id) = entry?.file_name().into_string()
            && valid_recording_id(&id)
            && Recording::load(root, &id).is_ok()
        {
            ids.push(id);
        }
    }
    ids.sort_unstable_by(|left, right| right.cmp(left));
    Ok(ids)
}

pub(super) fn is_full_commit_id(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64) && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_recording_id(id: &str) -> bool {
    id.len() == 14 && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_run_key(run_key: &str) -> Result<()> {
    ensure!(
        !run_key.is_empty()
            && !matches!(run_key, "." | "..")
            && run_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "run key must contain only ASCII letters, digits, '.', '_', or '-'"
    );
    Ok(())
}

fn recording_directory(target: &Path) -> PathBuf {
    target.join(LOCAL_ARTIFACTS_ROOT).join("recordings")
}

fn optional_entries(path: &Path) -> Result<Option<fs::ReadDir>> {
    match fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read directory {}", path.display())),
    }
}

fn matches_recording_key(round: &Round, recording_id: &str, key: &str) -> bool {
    round.recording_id == recording_id && round.run_key == key
}

fn read_rounds(path: &Path) -> Result<Option<BranchRounds>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse Replay round {}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read Replay round {}", path.display())),
    }
}

fn persist(path: &Path, rounds: &BranchRounds) -> Result<()> {
    let directory = path.parent().context("round path has no parent")?;
    fs::create_dir_all(directory)?;
    let temporary = directory.join(format!(".round-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, rounds)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.with_context(|| format!("save Replay round {}", path.display()))
}

fn open_lock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open Replay lock {}", path.display()))
}
