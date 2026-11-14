//! Finite case-owned upstream connection failures, before protocol exchange.
use super::*;
use crate::dependency::termination::ConnectionControl;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

const MAX_FAILURES: usize = 100_000;
const MAX_DURATION_MS: u64 = 86_400_000;
mod order;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct RecordedFailure {
    id: Uuid,
    timestamp: DateTime<Utc>,
    protocol: String,
    target_host: String,
    target_port: u16,
    duration_ms: u64,
    failure_kind: String,
    client_outcome: String,
}

impl RecordedFailure {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.target_host.is_empty()
                && self.target_host.len() <= 1024
                && !self.target_host.chars().any(char::is_control)
                && self.target_port > 0,
            "recorded connection failure has no bounded physical endpoint"
        );
        ensure!(
            self.duration_ms <= MAX_DURATION_MS
                && !self.failure_kind.is_empty()
                && self.failure_kind.len() <= 128
                && !self.failure_kind.chars().any(char::is_control)
                && self.client_outcome == "reset",
            "recorded connection failure has invalid transport evidence"
        );
        ensure!(
            !self.protocol.is_empty()
                && self.protocol.len() <= 1024
                && !self.protocol.chars().any(char::is_control),
            "recorded connection failure has an invalid protocol identity"
        );
        Ok(())
    }

    fn matches(&self, target: &ReplayTarget) -> bool {
        normalize_host(&self.target_host) == normalize_host(&target.host)
            && self.target_port == target.port
            && (self.protocol == "tcp" || self.protocol == target.protocol.id().as_str())
    }
}

#[derive(Debug)]
struct Entry {
    case_id: String,
    record: RecordedFailure,
    status: ReplayExchangeStatus,
    predecessors: Vec<control::dependency_tail::RecordedReference>,
}

#[derive(Debug, Default)]
pub(super) struct Inventory {
    entries: Vec<Entry>,
    by_id: BTreeMap<Uuid, usize>,
    dirty_cases: BTreeSet<String>,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct Report {
    matched_count: usize,
    unused_case: Vec<Observation>,
    failed_case: Vec<Observation>,
}

impl Report {
    pub(super) fn is_dirty(&self) -> bool {
        !self.unused_case.is_empty() || !self.failed_case.is_empty()
    }
}

#[derive(Debug, Serialize)]
struct Observation {
    case_id: String,
    target: TargetKey,
    #[serde(flatten)]
    record: RecordedFailure,
}

impl Inventory {
    pub(super) async fn load(
        &mut self,
        case_id: &str,
        path: &Path,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
        providers: &crate::protocols::DependencyProviders,
    ) -> Result<()> {
        let cleanup = super::lifecycle_cleanup::load_refs(
            &crate::dependency_index::scoped::case_directory(path)?,
        )
        .await?;
        let bytes = crate::dependency_index::scoped::read_bytes(path)?;
        let mut lines = tokio::io::BufReader::new(bytes.as_slice()).lines();
        while let Some(line) = lines.next_line().await? {
            if !line.contains("dependency_connect_failure") {
                continue;
            }
            let event: Value = serde_json::from_str(&line)?;
            if event["event_type"] != "dependency_connect_failure" {
                continue;
            }
            let record: RecordedFailure = serde_json::from_value(event)?;
            record.validate()?;
            let protocol = ReplayProtocol::resolve(
                if record.protocol == "tcp" {
                    "auto"
                } else {
                    &record.protocol
                },
                providers,
            )?;
            ensure!(
                cleanup.contains(&control::dependency_tail::RecordedReference::Connect {
                    event_id: record.id
                }) == (record.failure_kind == "engine_cancelled"),
                "engine-cancelled connection requires its exact authenticated Source-stop cleanup reference"
            );
            ensure!(
                self.entries.len() < MAX_FAILURES,
                "connection failure inventory exceeds its bound"
            );
            ensure!(
                !self.by_id.contains_key(&record.id),
                "recorded connection failure repeats its identity"
            );
            let target = TargetKey {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            };
            register_replay_target(targets, &target, protocol)?;
            self.by_id.insert(record.id, self.entries.len());
            self.entries.push(Entry {
                case_id: case_id.into(),
                record,
                status: ReplayExchangeStatus::Available,
                predecessors: Vec::new(),
            });
        }
        order::prepare(self, case_id, path).await?;
        Ok(())
    }

    pub(super) fn resolve(&self, case_id: &str, id: Uuid) -> Result<usize> {
        self.by_id
            .get(&id)
            .copied()
            .filter(|index| self.entries[*index].case_id == case_id)
            .context("async connection-failure reference is absent from its Case inventory")
    }

    pub(super) fn status(&self, index: usize) -> Option<ReplayExchangeStatus> {
        self.entries.get(index).map(|entry| entry.status)
    }

    pub(super) fn has_in_flight(&self) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry.status,
                ReplayExchangeStatus::Responding | ReplayExchangeStatus::AwaitingClientTermination
            )
        })
    }

    pub(super) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.dirty_cases.contains(case_id)
            || self
                .entries
                .iter()
                .any(|entry| entry.case_id == case_id && !entry.status.is_consumed())
    }

    pub(super) fn snapshot(&self) -> Report {
        let observation = |entry: &Entry| Observation {
            case_id: entry.case_id.clone(),
            target: TargetKey {
                host: normalize_host(&entry.record.target_host),
                port: entry.record.target_port,
            },
            record: entry.record.clone(),
        };
        Report {
            matched_count: self
                .entries
                .iter()
                .filter(|entry| entry.status.is_consumed())
                .count(),
            unused_case: self
                .entries
                .iter()
                .filter(|entry| {
                    entry.status != ReplayExchangeStatus::Failed && !entry.status.is_consumed()
                })
                .map(observation)
                .collect(),
            failed_case: self
                .entries
                .iter()
                .filter(|entry| entry.status == ReplayExchangeStatus::Failed)
                .map(observation)
                .collect(),
        }
    }
}

/// Claim a real Target connection once, then reproduce the observed peer
/// termination. Ordinary protocol dispatch owns connections with no such slot.
pub(super) async fn deliver(
    stream: &mut TcpStream,
    target: &ReplayTarget,
    state: &Arc<Mutex<ReplayState>>,
) -> Result<bool> {
    let (index, case_id, record) = {
        let mut state = state.lock().await;
        let Some(case) = state.active_case_id.clone() else {
            return Ok(false);
        };
        let Some(index) = state
            .connect_failures
            .entries
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.case_id == case && entry.status.is_available() && entry.record.matches(target)
            })
            .map(|(index, _)| index)
        else {
            return Ok(false);
        };
        if !control::dependency_tail::references_consumed(
            &state,
            &case,
            &state.connect_failures.entries[index].predecessors,
        )? {
            return Ok(false);
        }
        let entry = &mut state.connect_failures.entries[index];
        entry.status = ReplayExchangeStatus::Responding;
        (index, case, entry.record.clone())
    };
    let result = if record.failure_kind == "engine_cancelled" {
        let gate = state.lock().await.async_cleanup_gate(
            &case_id,
            control::dependency_tail::RecordedReference::Connect {
                event_id: record.id,
            },
        );
        if let Some(gate) = gate {
            state.lock().await.connect_failures.entries[index].status =
                ReplayExchangeStatus::AwaitingClientTermination;
            super::lifecycle_cleanup::await_connection_end(stream, &gate, state, &case_id).await
        } else {
            Err(anyhow!(
                "engine-cancelled connection lost its authenticated Source-stop cleanup context"
            ))
        }
    } else {
        terminate(stream, &record, state, &case_id).await
    };
    if result.is_err() {
        // The failure slot keeps its Case identity; stop the owned socket as
        // well when cancellation wins before its recorded peer termination.
        if let Ok(control) = ConnectionControl::new(stream) {
            let _ = control.reset();
        }
    }
    let mut state = state.lock().await;
    let accepted = result.is_ok()
        && state.active_case_id.as_deref() == Some(case_id.as_str())
        && state.finalized_at.is_none();
    state.connect_failures.entries[index].status = if accepted {
        ReplayExchangeStatus::Consumed
    } else {
        ReplayExchangeStatus::Failed
    };
    if !accepted {
        state.connect_failures.dirty_cases.insert(case_id);
    }
    result?;
    ensure!(
        accepted,
        "case ownership changed during connection-failure delivery"
    );
    Ok(true)
}

async fn terminate(
    stream: &mut TcpStream,
    record: &RecordedFailure,
    state: &Arc<Mutex<ReplayState>>,
    case: &str,
) -> Result<()> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(record.duration_ms);
    let mut buffer = [0; 8192];
    let case_deadline = control::dependency_tail::deadline(state, case).await;
    let mut lifecycle = tokio::time::interval(std::time::Duration::from_millis(25));
    loop {
        tokio::select! {
            biased;
            _ = async {
                if let Some(deadline) = case_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => anyhow::bail!("connection-failure delivery exceeded the common Case deadline"),
            _ = tokio::time::sleep_until(deadline) => break,
            _ = lifecycle.tick() => {
                let state = state.lock().await;
                ensure!(state.active_case_id.as_deref() == Some(case) && state.finalized_at.is_none(),
                    "connection-failure Case was closed before delivery");
            }
            read = stream.read(&mut buffer) => {
                let length = read.context("Target terminated before its recorded connection failure")?;
                ensure!(length > 0, "Target closed before its recorded connection failure");
            }
        }
    }
    let control = ConnectionControl::new(stream)?;
    ensure!(
        record.client_outcome == "reset",
        "unsupported recorded connection termination"
    );
    control.reset()?;
    Ok(())
}

#[cfg(test)]
mod tests;
