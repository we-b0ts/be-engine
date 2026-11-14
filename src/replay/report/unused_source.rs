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
pub(in crate::replay) struct CaptureFact {
    capture: CaptureMetadata,
    complete: bool,
    notification: bool,
}

impl CaptureFact {
    pub(in crate::replay) fn from_record(record: &Value) -> Option<Self> {
        if !(matches!(
            record["capture"]["protocol_ref"]["protocol"].as_str(),
            Some("mysql" | "redis")
        ) || record["event_type"] == "redis_pub_sub_push")
            || !crate::dependency_index::proof::is_evidence(record)
        {
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
            notification: record["event_type"] == "redis_pub_sub_push",
        })
    }
}

pub(crate) fn case_unused_rows(report: &Value) -> impl Iterator<Item = (&'static str, &Value)> {
    [
        ("mysql", &report["unused_case_exchanges"]),
        ("http", &report["unused_case_http_exchanges"]),
        ("redis", &report["redis"]["unused_case"]),
        ("memcached", &report["memcached"]["unused_case"]),
        ("motan", &report["motan"]["unused_case"]),
        ("kafka", &report["kafka"]["unused_case"]),
        ("network", &report["connect_failures"]["unused_case"]),
    ]
    .into_iter()
    .flat_map(|(protocol, rows)| {
        rows.as_array()
            .into_iter()
            .flatten()
            .map(move |row| (protocol, row))
    })
}

#[derive(Clone, Copy)]
enum Section {
    Mysql,
    Redis,
}

impl Section {
    fn rows(self, report: &Value) -> &Value {
        match self {
            Self::Mysql => &report["unused_case_exchanges"],
            Self::Redis => &report["redis"]["unused_case"],
        }
    }

    fn row_mut(self, report: &mut Value, position: usize) -> &mut Value {
        match self {
            Self::Mysql => &mut report["unused_case_exchanges"][position],
            Self::Redis => &mut report["redis"]["unused_case"][position],
        }
    }

    fn exchange_id(self, state: &ReplayState, case: &str, row: &Value) -> Option<Uuid> {
        if matches!(self, Self::Redis) && row["command"] == "PUBSUB_PUSH" {
            return explicit_exchange_id(row)?.parse().ok();
        }
        let index = usize::try_from(row["index"].as_u64()?).ok()?;
        match self {
            Self::Mysql => {
                let exchange = state.protocols.mysql.exchanges.get(index)?;
                if !exchange.source.matches_scope(ReplaySource::Case)
                    || exchange.case_id.as_deref() != Some(case)
                {
                    return None;
                }
                Some(exchange.record.capture.as_ref()?.exchange_id)
            }
            Self::Redis => state.protocols.redis.case_exchange_id(case, index),
        }
    }
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
                    previous.notification = fact.notification;
                }
            }
        }
    }
    by_id
}

fn select_case(
    state: &ReplayState,
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

pub(in crate::replay) fn attach(state: &ReplayState, report: &mut Value) -> usize {
    let Some(identity) = &state.source_inventory_id else {
        return 0;
    };
    let mut cases = BTreeMap::<String, Vec<_>>::new();
    for section in [Section::Mysql, Section::Redis] {
        for (position, row) in section
            .rows(report)
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if let Some(case) = row["case_id"].as_str()
                && let Some(id) = section.exchange_id(state, case, row)
            {
                cases
                    .entry(case.into())
                    .or_default()
                    .push((section, position, id));
            }
        }
    }
    let mut published = 0;
    for (case, rows) in cases {
        let wanted = rows.iter().map(|(_, _, id)| *id).collect();
        let facts = select_case(state, &case, &wanted);
        for (section, position, id) in rows {
            let Some(Some(fact)) = facts.get(&id) else {
                continue;
            };
            let row = section.row_mut(report, position);
            if (row["command"] == "PUBSUB_PUSH") != fact.notification {
                continue;
            }
            row[OCCURRENCE] = serde_json::json!(SourceOccurrence {
                source_exchange_id: id,
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
) -> Option<BTreeMap<Uuid, SourceOccurrence>> {
    if !has_published_occurrences(report) || report[INVENTORY] != inventory {
        return None;
    }
    let mut result = BTreeMap::new();
    for (protocol, row) in case_unused_rows(report) {
        if !row["case_id"]
            .as_str()
            .is_some_and(|case| cases.contains(case))
        {
            continue;
        }
        if !matches!(protocol, "mysql" | "redis") {
            return None;
        }
        let occurrence: SourceOccurrence =
            serde_json::from_value(row.get(OCCURRENCE)?.clone()).ok()?;
        if let Some(id) = explicit_exchange_id(row) {
            if id.parse::<Uuid>().ok()? != occurrence.source_exchange_id {
                return None;
            }
        } else if row["command"] == "PUBSUB_PUSH" {
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
