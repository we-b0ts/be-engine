//! Native contiguous transaction and script setup closure.
use super::{CaseFacts, Outcome, Prepared, admissible, assign, epoch, mysql, origins, problem};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

type Wire = (Uuid, String);
pub(super) struct Wires {
    connections: BTreeMap<Wire, BTreeMap<u64, usize>>,
    invalid: BTreeSet<Wire>,
}

fn wire(event: &Value) -> Option<(Wire, u64)> {
    (event["event_type"] == "mysql_exchange").then_some(())?;
    super::projection::native_identity(event).then_some(())?;
    Some((
        (epoch(event)?, event["connection_id"].as_str()?.into()),
        event["query_sequence"].as_u64()?,
    ))
}

fn status(event: &Value) -> Option<(u16, u16)> {
    Some((
        event["server_status_before"].as_u64()?.try_into().ok()?,
        event["response"]["server_status"]
            .as_u64()?
            .try_into()
            .ok()?,
    ))
}

impl Wires {
    pub fn new(events: &[Value]) -> Self {
        let mut result = Self {
            connections: BTreeMap::new(),
            invalid: BTreeSet::new(),
        };
        for (index, event) in events.iter().enumerate() {
            if let Some((key, sequence)) = wire(event)
                && result
                    .connections
                    .entry(key.clone())
                    .or_default()
                    .insert(sequence, index)
                    .is_some()
            {
                result.invalid.insert(key);
            }
        }
        result
    }

    pub fn committed(
        &self,
        events: &[Value],
        index: usize,
        case: Uuid,
        sql: &mysql::prepared::Matches<'_>,
    ) -> bool {
        let event = &events[index];
        let Some((key, sequence)) = wire(event) else {
            return false;
        };
        if self.invalid.contains(&key) {
            return false;
        }
        let Some((before, after)) = status(event) else {
            return false;
        };
        if before & 1 == 0 && after & 1 == 0 {
            return after & 2 != 0;
        }
        if after & 1 == 0 {
            return false;
        }
        let Some(connection) = self.connections.get(&key) else {
            return false;
        };
        let mut previous_sequence = sequence;
        let mut previous_status = after;
        for (&next, &index) in connection.range((
            std::ops::Bound::Excluded(sequence),
            std::ops::Bound::Unbounded,
        )) {
            let event = &events[index];
            let Some((before, after)) = status(event) else {
                return false;
            };
            if previous_sequence.checked_add(1) != Some(next)
                || before & 0x200b != previous_status & 0x200b
                || !mysql::successful(event)
            {
                return false;
            }
            let owner = event["capture"]["admitted_case"]
                .as_str()
                .or_else(|| event["capture"]["attribution"]["origin_case_id"].as_str())
                .and_then(|id| Uuid::parse_str(id).ok());
            if owner != Some(case) {
                return false;
            }
            // A successful ROLLBACK TO can erase the inserted row while leaving
            // IN_TRANS set. A later COMMIT does not prove that row survived.
            if sql.rollback(event) {
                return false;
            }
            match sql.boundary(event) {
                Some("commit") => return before & 1 == 1 && after & 1 == 0,
                Some("rollback" | "begin") => return false,
                _ => {
                    if after & 1 == 0 {
                        return false;
                    }
                }
            }
            previous_sequence = next;
            previous_status = after;
        }
        false
    }
}

pub(super) fn classify(
    prepared: &Prepared<'_>,
    origins: &[origins::Origin],
    inputs: &[CaseFacts],
    events: &[Value],
    wires: &Wires,
    outcome: &mut Outcome,
    conflicts: &mut BTreeSet<Uuid>,
) {
    let mut native_owned = BTreeSet::new();
    for (key, connection) in &wires.connections {
        if wires.invalid.contains(key) {
            continue;
        }
        let mut group = Vec::new();
        let mut previous: Option<(u64, u16)> = None;
        let mut cleanup: Option<&origins::Origin> = None;
        for (&sequence, &index) in connection {
            let event = &events[index];
            let Some((before, after)) = status(event) else {
                group.clear();
                previous = None;
                cleanup = None;
                continue;
            };
            let consecutive = previous.is_some_and(|(prior, flags)| {
                prior.checked_add(1) == Some(sequence) && flags & 0x200b == before & 0x200b
            });
            if !consecutive {
                group.clear();
                cleanup = None;
            }
            let boundary = prepared.sql.boundary(event);
            if group.is_empty()
                && boundary == Some("rollback")
                && before & 1 == 0
                && after & 1 == 0
                && mysql::successful(event)
                && idle_rollback(event, before, after, boundary)
            {
                if let Some(origin) = cleanup.take()
                    && admissible(origin, inputs, event, &origin.bindings)
                {
                    assign(outcome, conflicts, event, &origin.assignment);
                }
            } else if before & 1 == 0 && after & 1 == 1 {
                group.clear();
                group.push(index);
                cleanup = None;
            } else if !group.is_empty() && before & 1 == 1 {
                group.push(index);
            } else if before & 1 == 0
                && after & 1 == 0
                && boundary.is_none()
                && mysql::successful(event)
            {
                cleanup = None;
                if let Some(origin) = standalone(prepared, origins, inputs, event) {
                    assign(outcome, conflicts, event, &origin.assignment);
                } else if has_binding(prepared, origins, event) {
                    problem(outcome, event, None, "ambiguous_or_competing_ingress");
                }
            } else {
                cleanup = None;
            }
            if !group.is_empty() && matches!(boundary, Some("commit" | "rollback")) {
                let originally_owned =
                    original_single_case_group(prepared, origins, events, &group);
                if originally_owned {
                    native_owned.extend(
                        group
                            .iter()
                            .filter_map(|index| super::event_id(&events[*index])),
                    );
                }
                if let Some(origin) = prove(
                    prepared,
                    origins,
                    inputs,
                    events,
                    &group,
                    boundary == Some("rollback"),
                ) {
                    for &member in &group {
                        assign(outcome, conflicts, &events[member], &origin.assignment);
                    }
                    cleanup = Some(origin);
                } else if group
                    .iter()
                    .any(|index| has_binding(prepared, origins, &events[*index]))
                    && !originally_owned
                {
                    for &index in &group {
                        problem(
                            outcome,
                            &events[index],
                            None,
                            "unproven_transaction_membership",
                        );
                    }
                }
                group.clear();
            }
            previous = Some((sequence, after));
        }
    }
    for event in events {
        if has_binding(prepared, origins, event)
            && let Some(id) = super::event_id(event)
            && !outcome.decisions.contains_key(&id)
            && !outcome.unresolved.contains(&id)
            && !native_owned.contains(&id)
        {
            problem(outcome, event, None, "unproven_native_ownership");
        }
    }
}

fn original_single_case_group(
    prepared: &Prepared<'_>,
    origins: &[origins::Origin],
    events: &[Value],
    group: &[usize],
) -> bool {
    let mut owner = None;
    for &index in group {
        let event = &events[index];
        if !mysql::successful(event) {
            return false;
        }
        if event["command"] == "COM_PING" && event["capture"]["semantic_required"] == false {
            continue;
        }
        if !super::candidate_scope(event) || event["capture"]["attribution"]["kind"] != "case" {
            return false;
        }
        let Some(case) = event["capture"]["attribution"]["origin_case_id"].as_str() else {
            return false;
        };
        if event["capture"]["admitted_case"] != case
            || owner.is_some_and(|previous| previous != case)
        {
            return false;
        }
        owner = Some(case);
    }
    let Some(owner) = owner.and_then(|case| Uuid::parse_str(case).ok()) else {
        return false;
    };
    let candidates = origins
        .iter()
        .filter(|origin| {
            group
                .iter()
                .any(|index| binding_matches(prepared, origin, &events[*index]))
        })
        .map(|origin| origin.assignment.case_id)
        .collect::<BTreeSet<_>>();
    candidates.len() == 1 && candidates.contains(&owner)
}

fn has_binding(prepared: &Prepared<'_>, origins: &[origins::Origin], event: &Value) -> bool {
    if !super::candidate_scope(event) {
        return false;
    }
    origins
        .iter()
        .any(|origin| binding_matches(prepared, origin, event))
}

fn binding_matches(prepared: &Prepared<'_>, origin: &origins::Origin, event: &Value) -> bool {
    super::candidate_scope(event) && {
        epoch(event) == Some(origin.epoch)
            && super::started(event).is_some_and(|time| time >= origin.started_at)
            && origins::requests(prepared.rules, origin).any(|request| {
                prepared
                    .sql
                    .selector(request, event)
                    .is_some_and(|(bindings, _)| {
                        !bindings.is_empty()
                            && bindings
                                .iter()
                                .all(|(name, value)| origin.bindings.get(name) == Some(value))
                    })
            })
    }
}

fn idle_rollback(event: &Value, before: u16, after: u16, boundary: Option<&str>) -> bool {
    let response = &event["response"];
    event["command"] == "COM_QUERY"
        && boundary == Some("rollback")
        && (event["params"].is_null() || event["params"].as_array().is_some_and(Vec::is_empty))
        && response["status"] == "ok"
        && response["error_code"].is_null()
        && response["_error_absent"]
            .as_bool()
            .unwrap_or(response["error_message"].is_null())
        && response["affected_rows"].as_u64() == Some(0)
        && response["last_insert_id"].as_u64() == Some(0)
        && response["row_count"].as_u64() == Some(0)
        && response["rows_truncated"] == false
        && response["_rows_empty"]
            .as_bool()
            .unwrap_or_else(|| response["rows"].as_array().is_some_and(Vec::is_empty))
        && response["_columns_empty"]
            .as_bool()
            .unwrap_or_else(|| response["columns"].as_array().is_some_and(Vec::is_empty))
        && after & 0x2009 == 0
        && before & 2 == after & 2
}

fn standalone<'a>(
    prepared: &Prepared<'_>,
    origins: &'a [origins::Origin],
    inputs: &[CaseFacts],
    event: &Value,
) -> Option<&'a origins::Origin> {
    let mut selected = None;
    for origin in origins {
        if !origin.certain {
            continue;
        }
        if origins::requests(prepared.rules, origin).any(|request| {
            prepared
                .sql
                .selector(request, event)
                .is_some_and(|(bindings, _)| admissible(origin, inputs, event, &bindings))
        }) {
            if selected.is_some_and(|previous: &origins::Origin| {
                previous.assignment.case_id != origin.assignment.case_id
            }) {
                return None;
            }
            selected = Some(origin);
        }
    }
    selected
}

fn prove<'a>(
    prepared: &Prepared<'_>,
    origins: &'a [origins::Origin],
    inputs: &[CaseFacts],
    events: &[Value],
    group: &[usize],
    rollback: bool,
) -> Option<&'a origins::Origin> {
    let mut owners = Vec::new();
    for origin in origins {
        if !origin.certain {
            continue;
        }
        let mut anchored = false;
        let mut valid = true;
        for &index in group {
            let event = &events[index];
            if !mysql::successful(event) || epoch(event) != Some(origin.epoch) {
                valid = false;
                break;
            }
            if event["command"] == "COM_PING" && event["capture"]["semantic_required"] == false {
                continue;
            }
            if !admissible(origin, inputs, event, &origin.bindings) {
                valid = false;
                break;
            }
            if prepared.sql.boundary(event).is_some() {
                continue;
            }
            let mut matched = false;
            for request in origins::requests(prepared.rules, origin) {
                if let Some((bindings, member)) = prepared.sql.selector(request, event) {
                    if !bindings.is_empty() && admissible(origin, inputs, event, &bindings) {
                        anchored = true;
                        matched = true;
                    } else if bindings.is_empty() && member {
                        matched = true;
                    }
                }
            }
            if rollback && prepared.sql.write(event) {
                valid = false;
                break;
            }
            if !matched {
                valid = false;
                break;
            }
        }
        if valid && anchored {
            owners.push(origin);
        }
    }
    (owners.len() == 1).then(|| owners[0])
}

pub(super) fn potential(events: &[Value], selected: &BTreeSet<Uuid>) -> BTreeSet<Uuid> {
    let mut result = BTreeSet::new();
    let wires = Wires::new(events);
    for (key, connection) in &wires.connections {
        if wires.invalid.contains(key) {
            continue;
        }
        let mut group: Vec<usize> = Vec::new();
        let mut previous: Option<(u64, u16)> = None;
        let mut cleanup = false;
        for (&sequence, &index) in connection {
            let event = &events[index];
            let Some((before, after)) = status(event) else {
                group.clear();
                previous = None;
                cleanup = false;
                continue;
            };
            if !previous.is_some_and(|(prior, flags)| {
                prior.checked_add(1) == Some(sequence) && flags & 0x200b == before & 0x200b
            }) {
                group.clear();
                cleanup = false;
            }
            let boundary = mysql::boundary(event);
            if group.is_empty() && cleanup && idle_rollback(event, before, after, boundary) {
                if super::candidate_scope(event)
                    && let Some(id) = super::event_id(event)
                {
                    result.insert(id);
                }
                cleanup = false;
            } else if before & 1 == 0 && after & 1 == 1 {
                group.clear();
                group.push(index);
                cleanup = false;
            } else if !group.is_empty() && before & 1 == 1 {
                group.push(index);
            } else {
                cleanup = false;
            }
            if !group.is_empty() && matches!(boundary, Some("commit" | "rollback")) {
                if group.iter().any(|index| {
                    super::event_id(&events[*index]).is_some_and(|id| selected.contains(&id))
                }) {
                    for &index in &group {
                        if super::candidate_scope(&events[index])
                            && mysql::boundary(&events[index]).is_some()
                            && let Some(id) = super::event_id(&events[index])
                        {
                            result.insert(id);
                        }
                    }
                    cleanup = true;
                }
                group.clear();
            }
            previous = Some((sequence, after));
        }
    }
    result
}
