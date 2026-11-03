//! A closed, single-Case wire transaction owns its finite session rollback tail.
use super::*;
use crate::dependency::observation::RecordingManifest;
use std::collections::BTreeSet;

const TX: u16 = 0x2009;
type Windows = BTreeMap<Uuid, (DateTime<Utc>, DateTime<Utc>)>;

pub(super) struct Frame {
    capture: CaptureMetadata,
    connection: Uuid,
    sequence: u64,
    resource: Value,
    before: u16,
    after: u16,
    rollback: bool,
    captured_owner: Option<Uuid>,
    member_owner: Option<Uuid>,
}

impl Frame {
    pub(super) fn read(e: &Value, scope: Option<Uuid>, windows: &Windows) -> Result<Option<Self>> {
        if e["event_type"] != "mysql_exchange" {
            return Ok(None);
        }
        let (Some(raw), Some(connection), Some(sequence), Some(before), Some(after)) = (
            e.get("capture"),
            e["connection_id"]
                .as_str()
                .and_then(|id| id.parse::<Uuid>().ok()),
            e["query_sequence"].as_u64(),
            e["server_status_before"]
                .as_u64()
                .and_then(|f| u16::try_from(f).ok()),
            e["response"]["server_status"]
                .as_u64()
                .and_then(|f| u16::try_from(f).ok()),
        ) else {
            return Ok(None);
        };
        let capture: CaptureMetadata = serde_json::from_value(raw.clone())?;
        if raw["protocol_ref"]["protocol"] != "mysql"
            || raw["protocol_ref"]["connection_id"] != connection.to_string()
            || raw["protocol_ref"]["sequence"].as_u64() != Some(sequence)
        {
            return Ok(None);
        }
        let complete = crate::dependency_index::proof::capture_complete(e)
            && e["outcome"] == "response"
            && e["parse_warnings"].as_array().is_some_and(Vec::is_empty)
            && matches!(e["response"]["status"].as_str(), Some("ok" | "resultset"));
        let response = &e["response"];
        let rollback = complete
            && e["command"] == "COM_QUERY"
            && e["sql"].as_str().is_some_and(|sql| {
                let sql = sql.trim();
                sql.strip_suffix(';')
                    .unwrap_or(sql)
                    .trim()
                    .eq_ignore_ascii_case("ROLLBACK")
            })
            && (e["params"].is_null() || e["params"].as_array().is_some_and(Vec::is_empty))
            && response["status"] == "ok"
            && response["error_code"].is_null()
            && response["error_message"].is_null()
            && response["affected_rows"].as_u64() == Some(0)
            && response["last_insert_id"].as_u64() == Some(0)
            && response["row_count"].as_u64() == Some(0)
            && response["rows_truncated"] == false
            && response["rows"].as_array().is_some_and(Vec::is_empty)
            && response["columns"].as_array().is_some_and(Vec::is_empty)
            && after & TX == 0
            && before & 2 == after & 2;
        let captured_owner = match &capture.attribution {
            DependencyOwner::Case { origin_case_id, .. }
                if scope == Some(*origin_case_id)
                    && capture.admitted_case == Some(*origin_case_id) =>
            {
                Some(*origin_case_id)
            }
            _ => None,
        };
        let member_owner = captured_owner.filter(|case| {
            complete
                && windows.get(case).is_some_and(|(start, end)| {
                    *start <= capture.started_at && capture.started_at <= *end
                })
        });
        Ok(Some(Self {
            capture,
            connection,
            sequence,
            resource: serde_json::json!([
                e["target_host"],
                e["target_port"],
                e["database"],
                e["username"]
            ]),
            before,
            after,
            rollback,
            captured_owner,
            member_owner,
        }))
    }

    pub(super) fn candidate(&self) -> bool {
        self.rollback
            && self.capture.phase == CapturePhase::Runtime
            && self.capture.semantic_required
            && self.capture.observed_case.is_some()
            && self.capture.admitted_case.is_none()
            && self.capture.matched_rule_id.is_none()
            && self.capture.matched_rule_ids.is_empty()
            && matches!(&self.capture.attribution, DependencyOwner::Unattributed { reason } if reason == "outside_admission")
    }

    fn closes(&self, case: Uuid) -> bool {
        self.rollback
            && (self.captured_owner == Some(case)
                || (self.candidate() && self.capture.observed_case == Some(case)))
    }
}

pub(super) fn extend(
    root: &Path,
    manifest: &RecordingManifest,
    windows: &Windows,
    unowned: Vec<Frame>,
    defaults: &mut BTreeMap<Uuid, DependencyOwner>,
) -> Result<()> {
    let connections: BTreeSet<_> = unowned
        .iter()
        .filter(|e| e.candidate())
        .map(|e| e.connection)
        .collect();
    if connections.is_empty() {
        return Ok(());
    }
    let mut frames = unowned
        .into_iter()
        .filter(|e| connections.contains(&e.connection))
        .collect::<Vec<_>>();
    for input in &manifest.inputs {
        if !input.complete || !windows.contains_key(&input.case_id) {
            continue;
        }
        let path = root
            .join(&input.path)
            .join(crate::dependency_index::scoped::CASE_SCOPE);
        if !path.is_file() {
            continue;
        }
        let mut stream = crate::dependency_index::RecordStream::open(&path)?;
        while let Some((_, bytes)) = stream.next()? {
            if bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let e: Value = serde_json::from_slice(bytes)?;
            if !e["connection_id"]
                .as_str()
                .and_then(|id| id.parse::<Uuid>().ok())
                .is_some_and(|id| connections.contains(&id))
            {
                continue;
            }
            if let Some(frame) = Frame::read(&e, Some(input.case_id), windows)? {
                frames.push(frame);
            }
        }
    }
    for (id, case) in prove(frames) {
        let owner = DependencyOwner::Case {
            origin_case_id: case,
            task_instance: None,
        };
        ensure!(
            defaults
                .insert(id, owner.clone())
                .is_none_or(|old| old == owner),
            "contradictory native Case cleanup identity"
        );
    }
    Ok(())
}

fn prove(frames: Vec<Frame>) -> BTreeMap<Uuid, Uuid> {
    let mut connections = BTreeMap::<Uuid, BTreeMap<u64, Frame>>::new();
    let mut ambiguous = BTreeSet::new();
    for frame in frames {
        let connection = frame.connection;
        if connections
            .entry(connection)
            .or_default()
            .insert(frame.sequence, frame)
            .is_some()
        {
            ambiguous.insert(connection);
        }
    }
    let mut owners = BTreeMap::new();
    for (connection, frames) in connections {
        if ambiguous.contains(&connection) {
            continue;
        }
        let mut previous: Option<&Frame> = None;
        let mut transaction: Option<Uuid> = None;
        let mut cleanup: Option<Uuid> = None;
        for frame in frames.values() {
            let consecutive = previous.is_some_and(|p| {
                p.sequence.checked_add(1) == Some(frame.sequence)
                    && p.after & 0x200b == frame.before & 0x200b
                    && p.resource == frame.resource
                    && p.capture.process_epoch == frame.capture.process_epoch
            });
            if !consecutive {
                transaction = None;
                cleanup = None;
            }
            match (frame.before & TX, frame.after & TX) {
                (0, 1) => {
                    transaction = frame.member_owner;
                    cleanup = None;
                }
                (1, 1) => {
                    transaction = transaction.filter(|case| frame.member_owner == Some(*case));
                    cleanup = None;
                }
                (1, 0) => {
                    cleanup = transaction.take().filter(|case| frame.closes(*case));
                    if let Some(case) = cleanup
                        && frame.candidate()
                    {
                        owners.insert(frame.capture.exchange_id, case);
                    }
                }
                (0, 0) => {
                    // Exactly one adjacent idle rollback can release the same
                    // proven session. Never inherit an unbounded control run.
                    if let Some(case) = cleanup
                        .take()
                        .filter(|case| consecutive && frame.closes(*case))
                        && frame.candidate()
                    {
                        owners.insert(frame.capture.exchange_id, case);
                    }
                    transaction = None;
                }
                _ => {
                    transaction = None;
                    cleanup = None;
                }
            }
            previous = Some(frame);
        }
    }
    owners
}

#[cfg(test)]
mod tests;
