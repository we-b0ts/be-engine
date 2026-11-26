//! Match coverage and ownership decisions for a failed attempt's Source window.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::{
    config::api_catalog,
    session::{DispatchWindow, WindowMatchKind, WindowOwner},
};
use uuid::Uuid;

use super::{
    Ownership, Registration, Task, WorkItem, Workflow, read_sequence_file, validate_scope,
};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Window {
    pub from_seq: u64,
    pub through_seq: u64,
    #[serde(default)]
    pub attempt_id: Option<Uuid>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        with = "sequence_entries"
    )]
    requests: BTreeMap<u64, WindowOwner>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        with = "sequence_entries"
    )]
    unmatched: BTreeMap<u64, WindowMatchKind>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        with = "sequence_entries"
    )]
    unresolved: BTreeMap<u64, (WindowMatchKind, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    proofs: Vec<OwnershipProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<Registration>,
}

mod sequence_entries {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    // Round deserialization flattens Workflow into a generic Serde value.
    // Sequence values preserve their numeric type when represented as list entries.
    pub(super) fn serialize<S: Serializer, V: Serialize>(
        entries: &BTreeMap<u64, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(entries)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<u64, V>, D::Error> {
        let entries = Vec::<(u64, V)>::deserialize(deserializer)?;
        let length = entries.len();
        let entries: BTreeMap<_, _> = entries.into_iter().collect();
        if entries.len() != length {
            return Err(D::Error::custom(
                "duplicate Source sequence in lookahead snapshot",
            ));
        }
        Ok(entries)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct OwnershipProof {
    sequences: BTreeSet<u64>,
    evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_seq: Option<u64>,
}

impl Window {
    pub(super) fn handoff(&self) -> Value {
        json!({
            "from_seq": self.from_seq,
            "through_seq": self.through_seq,
            "pending_ownership": self.unmatched.len(),
            "unresolved": self.unresolved.len(),
        })
    }

    fn task(&self, run_key: &str, attempt_id: Uuid) -> Task {
        Task::lookahead(
            run_key,
            &attempt_id.simple().to_string(),
            self.from_seq,
            self.through_seq,
            self.unmatched.len(),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowFinding {
    sequences_file: PathBuf,
    scope: Option<String>,
    group: Option<String>,
    evidence: String,
}

impl Workflow {
    pub(super) fn observe_window(
        &mut self,
        base: &str,
        attempt_id: Uuid,
        seq: u64,
        dispatch: DispatchWindow,
    ) -> Result<()> {
        let (unresolved, proofs) = self
            .window
            .take()
            .map(|window| (window.unresolved, window.proofs))
            .unwrap_or_default();
        let mut window = Window {
            from_seq: dispatch.from_seq,
            through_seq: dispatch.through_seq,
            attempt_id: Some(attempt_id),
            requests: BTreeMap::new(),
            unmatched: BTreeMap::new(),
            unresolved,
            proofs,
            registration: None,
        };
        let bounds = window.from_seq..=window.through_seq;
        window
            .unresolved
            .retain(|event, _| bounds.contains(event) && *event != seq);
        window.proofs.retain_mut(|proof| {
            proof.sequences.retain(|event| bounds.contains(event));
            !proof.sequences.is_empty()
        });
        self.groups.retain_lookahead(bounds.clone());
        let ready: BTreeSet<_> = self
            .groups
            .ready_fixes()
            .flat_map(|fix| {
                fix.sequences
                    .iter()
                    .map(|&sequence| (fix.group.as_str(), sequence))
            })
            .collect();
        let mut work = BTreeMap::<(String, String), BTreeSet<u64>>::new();
        for (sequence, entry) in dispatch.matches {
            if entry.kind == WindowMatchKind::PrimaryRequest
                && let Some(owner) = entry.owner.as_ref().filter(|owner| owner.group.is_some())
            {
                window.requests.insert(sequence, owner.clone());
            }
            if sequence == seq {
                continue;
            }
            let owner = self.owners.get(&sequence.to_string()).cloned().or_else(|| {
                let owner = entry.owner?;
                Some(Ownership {
                    seq: sequence,
                    scope: owner.scope,
                    group: owner.group?,
                })
            });
            if let Some(owner) = owner {
                if !ready.contains(&(owner.group.as_str(), sequence))
                    && !self.ready_rule_covers(&owner.group, sequence)
                    && self.groups.gap(&owner.group, sequence).is_none()
                {
                    work.entry((owner.group, owner.scope))
                        .or_default()
                        .insert(sequence);
                }
            } else if !window.unresolved.contains_key(&sequence) {
                window.unmatched.insert(sequence, entry.kind);
            }
        }
        for ((group, scope), sequences) in work {
            self.groups.reopen(
                &group,
                WorkItem {
                    scope,
                    sequences,
                    apis: Vec::new(),
                },
                base,
            );
        }
        let repeated = self
            .failure
            .as_ref()
            .is_some_and(|failure| failure.seq == seq);
        self.window = Some(window);
        self.failure = Some(super::Failure { attempt_id, seq });
        if let Some(owner) = self.failure_owner(seq).cloned() {
            if repeated {
                self.groups.dismiss_gap(&owner.group, seq);
            }
            self.enqueue_owner(&owner, base);
        } else if let Some(owner) = dispatch.failure_owner
            && let Some(group) = owner.group
        {
            self.set_owner(
                Ownership {
                    seq,
                    scope: owner.scope,
                    group,
                },
                base,
            )?;
        }
        self.groups.release_empty_lookahead_assignments();
        Ok(())
    }

    pub fn lookahead_task(&self, run_key: &str, attempt_id: &str) -> Option<Task> {
        let window = self.window.as_ref()?;
        if window.unmatched.is_empty() {
            return None;
        }
        self.lookahead_delivery_task(run_key, attempt_id)
    }

    pub fn lookahead_delivery_task(&self, run_key: &str, attempt_id: &str) -> Option<Task> {
        let window = self.window.as_ref()?;
        let attempt_id = attempt_id.parse::<Uuid>().ok()?;
        (window.attempt_id == Some(attempt_id)).then(|| window.task(run_key, attempt_id))
    }

    pub fn can_dispatch_lookahead(&self) -> bool {
        self.groups.pending_dispatch() == 0 && self.groups.pending_worker_status() == 0
    }

    pub fn lookahead_task_sequences(&self, run_key: &str, task_id: &str) -> Result<BTreeSet<u64>> {
        let window = self.window.as_ref().context("no active lookahead window")?;
        let attempt = window
            .attempt_id
            .context("inspect status to refresh the lookahead window")?;
        let task = window.task(run_key, attempt);
        ensure!(task.id() == task_id, "stale lookahead task; inspect status");
        Ok(window.unmatched.keys().copied().collect())
    }

    pub fn apply_lookahead_findings(
        &mut self,
        root: &Path,
        base: &str,
        directory: &Path,
        findings: Vec<WindowFinding>,
    ) -> Result<()> {
        let window = self.window.as_mut().context("no active lookahead window")?;
        ensure!(
            !findings.is_empty(),
            "submit at least one lookahead finding"
        );
        let mut covered = BTreeSet::new();
        for finding in findings {
            ensure!(
                !finding.evidence.trim().is_empty(),
                "lookahead findings require evidence"
            );
            let sequences = read_sequence_file(&directory.join(finding.sequences_file))?;
            let owner = match (finding.scope, finding.group) {
                (Some(scope), Some(group)) => {
                    api_catalog::validate_group(&group)?;
                    validate_scope(&scope)?;
                    let mut owner = Ownership {
                        seq: 0,
                        scope,
                        group,
                    };
                    owner.resolve_api(root)?;
                    Some(owner)
                }
                (None, None) => None,
                _ => anyhow::bail!("lookahead ownership requires both scope and group"),
            };
            let mut pending = BTreeSet::new();
            for seq in sequences {
                ensure!(covered.insert(seq), "seq {seq} appears in several findings");
                if window.unmatched.contains_key(&seq)
                    || (owner.is_some() && window.unresolved.contains_key(&seq))
                {
                    pending.insert(seq);
                    continue;
                }
                let accepted = self
                    .owners
                    .get(&seq.to_string())
                    .filter(|_| (window.from_seq < seq) && (seq <= window.through_seq));
                ensure!(
                    accepted.is_some_and(|accepted| owner.as_ref().is_none_or(|owner| {
                        (accepted.group == owner.group) && (accepted.scope == owner.scope)
                    })) || (owner.is_none() && window.unresolved.contains_key(&seq)),
                    "seq {seq} is not an outstanding or matching ownership decision for this task"
                );
            }
            match owner {
                Some(owner) if !pending.is_empty() => {
                    window.proofs.push(OwnershipProof {
                        sequences: pending.clone(),
                        evidence: finding.evidence,
                        request_seq: None,
                    });
                    for &seq in &pending {
                        self.owners.insert(
                            seq.to_string(),
                            Ownership {
                                seq,
                                ..owner.clone()
                            },
                        );
                        window.unresolved.remove(&seq);
                    }
                    self.groups.reopen(
                        &owner.group,
                        WorkItem {
                            scope: owner.scope,
                            sequences: pending,
                            apis: Vec::new(),
                        },
                        base,
                    );
                }
                Some(_) => {}
                None => {
                    for seq in pending {
                        if let Some(kind) = window.unmatched.get(&seq) {
                            window
                                .unresolved
                                .insert(seq, (*kind, finding.evidence.clone()));
                        }
                    }
                }
            }
        }
        window.unmatched.retain(|seq, _| !covered.contains(seq));
        Ok(())
    }

    pub(super) fn claim(&mut self, claim: Claim) -> Result<()> {
        let window = self.window.as_mut().context("no active lookahead window")?;
        let base = self
            .groups
            .assignment_base(&claim.group, claim.assignment_id)?
            .to_owned();
        ensure!(
            !claim.evidence.trim().is_empty(),
            "a claim requires Source ownership evidence"
        );
        ensure!(
            !claim.sequences.is_empty(),
            "a claim requires dependency sequences"
        );
        ensure!(
            window
                .requests
                .get(&claim.request_seq)
                .is_some_and(|request| {
                    (request.group.as_deref() == Some(claim.group.as_str()))
                        && (request.scope == claim.scope)
                }),
            "claim must reference a primary request in the assignment's API scope and active window",
        );
        let mut new = BTreeSet::new();
        for seq in claim.sequences {
            ensure!(
                seq > claim.request_seq,
                "dependency seq {seq} must follow its primary request"
            );
            if self
                .owners
                .get(&seq.to_string())
                .is_some_and(|owner| (owner.group == claim.group) && (owner.scope == claim.scope))
                && window.from_seq < seq
                && seq <= window.through_seq
            {
                continue;
            }
            let kind = window
                .unmatched
                .get(&seq)
                .copied()
                .or_else(|| window.unresolved.get(&seq).map(|(kind, _)| *kind));
            ensure!(
                kind == Some(WindowMatchKind::DependencyRequest),
                "seq {seq} is not an unowned dependency admission in the active window"
            );
            new.insert(seq);
        }
        if !new.is_empty() {
            window.proofs.push(OwnershipProof {
                sequences: new.clone(),
                evidence: claim.evidence,
                request_seq: Some(claim.request_seq),
            });
            for &seq in &new {
                window.unmatched.remove(&seq);
                window.unresolved.remove(&seq);
                self.owners.insert(
                    seq.to_string(),
                    Ownership {
                        seq,
                        scope: claim.scope.clone(),
                        group: claim.group.clone(),
                    },
                );
            }
            self.groups.reopen(
                &claim.group,
                WorkItem {
                    scope: claim.scope,
                    sequences: new,
                    apis: Vec::new(),
                },
                &base,
            );
        }
        Ok(())
    }

    pub fn assignment_sequences(&self, id: Uuid, scope: Option<&str>) -> Result<BTreeSet<u64>> {
        self.groups.assignment_sequences(id, scope)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claim {
    group: String,
    assignment_id: Uuid,
    scope: String,
    request_seq: u64,
    sequences: BTreeSet<u64>,
    evidence: String,
}

pub(super) fn api_scope_path(scope: &str) -> Option<&str> {
    let api = scope.strip_prefix("api:")?;
    if api.starts_with('/') {
        return (!api.contains(char::is_whitespace)).then_some(api);
    }
    let (method, path) = api.split_once(' ')?;
    (!method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
        && path.starts_with('/')
        && !path.contains(char::is_whitespace))
    .then_some(path)
}
