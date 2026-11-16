//! Source capture facts carried by the finalized Case report.
use super::*;
use crate::dependency::{attribution::DependencyOwner, observation::CaptureMetadata};

const INVENTORY: &str = "unused_source_inventory_id";
const OCCURRENCE: &str = "source_occurrence";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SourceOccurrence {
    pub source_exchange_id: Uuid,
    pub captured_owner: DependencyOwner,
    pub capture_complete: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct CaptureFact {
    capture: CaptureMetadata,
    complete: bool,
    event_type: String,
}

impl CaptureFact {
    pub(crate) fn from_record(record: &Value) -> Option<Self> {
        if !crate::dependency_index::proof::is_evidence(record) {
            return None;
        }
        Self::parse(
            record,
            crate::dependency_index::proof::capture_complete(record),
        )
    }

    fn parse(record: &Value, complete: bool) -> Option<Self> {
        Some(Self {
            capture: serde_json::from_value(record.get("capture")?.clone()).ok()?,
            complete,
            event_type: record["event_type"].as_str()?.into(),
        })
    }
}

pub(crate) fn case_unused_rows<'a>(
    report: &'a Value,
    codecs: &traffic_protocol::report::CodecRegistry,
) -> impl Iterator<Item = (&'a str, &'a Value)> {
    let mut rows = Vec::new();
    for (protocol, codec) in codecs.iter() {
        if report["dependency_protocols"]
            .get(protocol.as_str())
            .is_some()
        {
            continue;
        }
        rows.extend(
            codec
                .unused_case_rows(report, protocol.as_str())
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| (protocol.as_str(), row)),
        );
    }
    for (protocol, section) in report["dependency_protocols"]
        .as_object()
        .into_iter()
        .flatten()
    {
        rows.extend(
            section["unused_case"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|row| (protocol.as_str(), row)),
        );
    }
    rows.extend(
        report["connect_failures"]["unused_case"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| ("network", row)),
    );
    rows.into_iter()
}

fn explicit_exchange_id(row: &Value) -> Option<&str> {
    row["source_exchange_id"]
        .as_str()
        .or_else(|| row["capture"]["exchange_id"].as_str())
}

fn fold(facts: impl Iterator<Item = CaptureFact>) -> BTreeMap<Uuid, Option<CaptureFact>> {
    use std::collections::btree_map::Entry;
    let mut by_id = BTreeMap::new();
    for fact in facts {
        match by_id.entry(fact.capture.exchange_id) {
            Entry::Vacant(entry) => {
                entry.insert(Some(fact));
            }
            Entry::Occupied(mut entry) => {
                let Some(previous) = entry.get_mut() else {
                    continue;
                };
                if previous.capture.process_epoch != fact.capture.process_epoch
                    || previous.capture.protocol_ref != fact.capture.protocol_ref
                    || previous.capture.started_at != fact.capture.started_at
                    || previous.capture.attribution != fact.capture.attribution
                {
                    entry.insert(None);
                    continue;
                }
                previous.complete &= fact.complete;
                if fact.capture.semantic_required && !previous.capture.semantic_required {
                    previous.capture = fact.capture;
                    previous.event_type = fact.event_type;
                }
            }
        }
    }
    by_id
}

fn select_case<P: ReplayProtocolSet>(
    state: &RuntimeState<P>,
    case: &str,
    wanted: &BTreeSet<Uuid>,
) -> BTreeMap<Uuid, Option<CaptureFact>> {
    if let Some(deferred) = &state.deferred {
        let records = deferred
            .files
            .get(case)
            .and_then(|case| case.index.proof_records.as_ref());
        fold(records.into_iter().flatten().filter_map(|record| {
            let selector = &record.selector;
            let id = selector["capture"]["exchange_id"]
                .as_str()?
                .parse::<Uuid>()
                .ok()?;
            wanted
                .contains(&id)
                .then(|| CaptureFact::parse(selector, selector["_capture_complete"] == true))
                .flatten()
        }))
    } else {
        fold(
            state
                .eager_source_facts
                .get(case)
                .into_iter()
                .flatten()
                .filter(|fact| wanted.contains(&fact.capture.exchange_id))
                .cloned(),
        )
    }
}

/// A native adapter supplies report locations and the expected Source evidence kind.
pub(crate) struct SourceRow {
    pub pointer: String,
    pub case: String,
    pub exchange_id: Uuid,
    pub identity: SourceIdentity,
}

pub(crate) enum SourceIdentity {
    Reference(RecordedReference),
    EventType(&'static str),
}

pub(crate) fn attach<P: ReplayProtocolSet>(state: &RuntimeState<P>, report: &mut Value) -> usize {
    let Some(identity) = &state.source_inventory_id else {
        return 0;
    };
    let mut cases = BTreeMap::<String, Vec<SourceRow>>::new();
    for row in state
        .native
        .source_occurrence_rows(report)
        .into_iter()
        .chain(P::source_occurrence_rows(state, report))
    {
        cases.entry(row.case.clone()).or_default().push(row);
    }
    let mut published = 0;
    for (case, rows) in cases {
        let wanted = rows.iter().map(|row| row.exchange_id).collect();
        let facts = select_case(state, &case, &wanted);
        for source in rows {
            let Some(Some(fact)) = facts.get(&source.exchange_id) else {
                continue;
            };
            let matches = match source.identity {
                SourceIdentity::Reference(reference) => reference == fact.capture.protocol_ref,
                SourceIdentity::EventType(event_type) => event_type == fact.event_type,
            };
            if !matches {
                continue;
            }
            let Some(row) = report.pointer_mut(&source.pointer) else {
                continue;
            };
            if row["case_id"].as_str() != Some(&case) {
                continue;
            }
            row[OCCURRENCE] = serde_json::json!(SourceOccurrence {
                source_exchange_id: source.exchange_id,
                captured_owner: fact.capture.attribution.clone(),
                capture_complete: fact.complete,
            });
            published += 1;
        }
    }
    report[INVENTORY] = serde_json::json!(identity);
    published
}

pub(crate) fn has_published_occurrences(report: &Value) -> bool {
    report["finalized"] == true && report[INVENTORY].is_string()
}

pub(crate) fn published_for_cases(
    report: &Value,
    inventory: &str,
    cases: &BTreeSet<String>,
    codecs: &traffic_protocol::report::CodecRegistry,
) -> Option<BTreeMap<Uuid, SourceOccurrence>> {
    if !has_published_occurrences(report) || report[INVENTORY] != inventory {
        return None;
    }
    let mut result = BTreeMap::new();
    for (protocol, row) in case_unused_rows(report, codecs) {
        if !row["case_id"]
            .as_str()
            .is_some_and(|case| cases.contains(case))
        {
            continue;
        }
        let codec = codecs.codec(protocol);
        if report["dependency_protocols"].get(protocol).is_none()
            && codec
                .as_ref()
                .is_some_and(|codec| !codec.supports_source_occurrences())
        {
            return None;
        }
        let occurrence: SourceOccurrence =
            serde_json::from_value(row.get(OCCURRENCE)?.clone()).ok()?;
        if let Some(id) = explicit_exchange_id(row) {
            if id.parse::<Uuid>().ok()? != occurrence.source_exchange_id {
                return None;
            }
        } else if codec
            .as_ref()
            .is_some_and(|codec| codec.requires_source_exchange_id(row))
        {
            return None;
        }
        if let Some(previous) = result.insert(occurrence.source_exchange_id, occurrence.clone())
            && previous != occurrence
        {
            return None;
        }
    }
    Some(result)
}
