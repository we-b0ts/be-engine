//! Scoped specialist task identities and dispatch-to-delivery transitions.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use traffic_e2e::policy_evidence;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Registration {
    pub task_id: String,
    pub agent_handle: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DispatchState {
    Started,
    Exited,
}

enum Requirement {
    Grouping {
        ungrouped_apis: usize,
    },
    Ownership {
        attempt_id: String,
        seq: u64,
    },
    Integration {
        attempt_id: String,
        ready_fixes: usize,
        seq: Option<u64>,
    },
}

pub(crate) struct Task {
    id: String,
    requirement: Requirement,
}

impl Task {
    pub fn grouping(recording_id: &str, run_key: &str, head: &str, ungrouped_apis: usize) -> Self {
        Self::new(
            json!(["api_grouping_required", recording_id, run_key, head]),
            Requirement::Grouping { ungrouped_apis },
        )
    }

    pub fn ownership(run_key: &str, attempt_id: &str, seq: u64) -> Self {
        Self::new(
            json!(["ownership_required", run_key, attempt_id, seq]),
            Requirement::Ownership {
                attempt_id: attempt_id.to_owned(),
                seq,
            },
        )
    }

    pub fn integration(
        run_key: &str,
        attempt_id: &str,
        ready_fixes: usize,
        seq: Option<u64>,
    ) -> Self {
        Self::new(
            json!(["integration_required", run_key, attempt_id, seq]),
            Requirement::Integration {
                attempt_id: attempt_id.to_owned(),
                ready_fixes,
                seq,
            },
        )
    }

    fn new(scope: Value, requirement: Requirement) -> Self {
        Self {
            id: policy_evidence::digest(scope.to_string().as_bytes()),
            requirement,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_grouping(&self) -> bool {
        matches!(self.requirement, Requirement::Grouping { .. })
    }

    pub fn is_ownership(&self) -> bool {
        matches!(self.requirement, Requirement::Ownership { .. })
    }

    pub fn action(&self, registration: Option<&Registration>) -> Value {
        let (role, mut task) = match &self.requirement {
            Requirement::Grouping { ungrouped_apis } => (
                "issue-analyst",
                json!({
                    "requirement":"api_grouping_required",
                    "ungrouped_apis":ungrouped_apis
                }),
            ),
            Requirement::Ownership { attempt_id, seq } => (
                "issue-analyst",
                json!({
                    "requirement":"ownership_required", "attempt_id":attempt_id, "seq":seq
                }),
            ),
            Requirement::Integration {
                attempt_id,
                ready_fixes,
                seq,
            } => {
                let mut task = json!({
                    "requirement":"integration_required", "attempt_id":attempt_id, "ready_fixes":ready_fixes
                });
                if let Some(seq) = seq {
                    task["seq"] = json!(seq);
                }
                ("code-integrator", task)
            }
        };
        task["role"] = json!(role);
        task["task_id"] = json!(self.id());
        let (kind, summary) = if let Some(registration) = self.matching(registration) {
            task["agent_handle"] = json!(registration.agent_handle);
            (
                "await_delivery",
                format!(
                    "Follow the registered {role} agent. Submit its reviewed delivery after it returns."
                ),
            )
        } else {
            (
                "dispatch_task",
                format!(
                    "Launch a {role} agent with this task's context. Register the handle returned by the runtime."
                ),
            )
        };
        json!({"kind":kind, "summary":summary, "details":{"task":task}})
    }

    pub fn register(
        &self,
        current: &mut Option<Registration>,
        update: Registration,
        state: DispatchState,
    ) -> Result<()> {
        ensure!(
            update.task_id == self.id(),
            "dispatch receipt is for a stale task"
        );
        ensure!(
            !update.agent_handle.trim().is_empty()
                && update.agent_handle.len() <= 4096
                && !update.agent_handle.chars().any(char::is_control),
            "invalid specialist agent_handle"
        );
        let registered = self.matching(current.as_ref());
        match state {
            DispatchState::Started => {
                ensure!(
                    registered.is_none_or(|registered| registered == &update),
                    "task already has a different registered agent handle; report its exit before replacing it"
                );
                *current = Some(update);
            }
            DispatchState::Exited => {
                ensure!(
                    registered == Some(&update),
                    "exit receipt must match the current registered task and agent handle"
                );
                *current = None;
            }
        }
        Ok(())
    }

    pub fn require_delivery(
        &self,
        current: Option<&Registration>,
        binding: &Registration,
    ) -> Result<()> {
        ensure!(binding.task_id == self.id(), "delivery is for a stale task");
        ensure!(
            self.matching(current) == Some(binding),
            "delivery must match the current registered task and agent handle"
        );
        Ok(())
    }

    fn matching<'a>(&self, registration: Option<&'a Registration>) -> Option<&'a Registration> {
        registration.filter(|value| value.task_id == self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_identity_tracks_scope_and_ignores_work_counts() {
        let grouping = Task::grouping("recording-a", "round", "head", 1);
        assert_eq!(
            grouping.id(),
            Task::grouping("recording-a", "round", "head", 3).id()
        );
        assert_ne!(
            grouping.id(),
            Task::grouping("recording-b", "round", "head", 1).id()
        );
        assert_ne!(
            grouping.id(),
            Task::grouping("recording-a", "round", "other-head", 1).id()
        );

        let integration = Task::integration("round", "attempt", 1, Some(5));
        assert_eq!(
            integration.id(),
            Task::integration("round", "attempt", 2, Some(5)).id()
        );
        assert_ne!(
            integration.id(),
            Task::integration("round", "attempt", 1, Some(6)).id()
        );
        assert_ne!(
            integration.id(),
            Task::ownership("round", "attempt", 5).id()
        );
    }

    #[test]
    fn deliveries_require_current_registration() {
        let task = Task::ownership("round", "attempt", 5);
        let first = Registration {
            task_id: task.id().to_owned(),
            agent_handle: "first".into(),
        };
        let replacement = Registration {
            agent_handle: "replacement".into(),
            ..first.clone()
        };
        let mut current = None;
        assert!(task.require_delivery(current.as_ref(), &first).is_err());
        task.register(&mut current, first.clone(), DispatchState::Started)
            .unwrap();
        task.register(&mut current, first.clone(), DispatchState::Started)
            .unwrap();
        assert!(
            task.register(&mut current, replacement.clone(), DispatchState::Started)
                .is_err()
        );
        task.register(&mut current, first.clone(), DispatchState::Exited)
            .unwrap();
        task.register(&mut current, replacement.clone(), DispatchState::Started)
            .unwrap();
        assert!(
            task.register(&mut current, first.clone(), DispatchState::Exited)
                .is_err()
        );
        assert!(task.require_delivery(current.as_ref(), &first).is_err());
        task.require_delivery(current.as_ref(), &replacement)
            .unwrap();
    }
}
