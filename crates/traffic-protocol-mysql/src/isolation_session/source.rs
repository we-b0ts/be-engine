//! A complete original SESSION override, one transaction and restoration.
use super::*;

#[derive(Debug, Clone)]
pub struct Baseline {
    connection: Uuid,
    completed_at: Option<DateTime<Utc>>,
    pub identity: MysqlDependencyIdentity,
    sequence: u64,
    pub level: Level,
}

#[derive(Debug)]
pub struct Plan {
    pub identity: MysqlDependencyIdentity,
    pub case: String,
    pub source_connection: Uuid,
    pub sequence: u64,
    pub baseline_sequence: u64,
    pub baseline_connection: Uuid,
    pub baseline: Level,
    pub level: Level,
    pub setup: usize,
    pub end: usize,
    pub reset: usize,
    pub reassertions: BTreeSet<usize>,
    pub required: BTreeSet<usize>,
    pub read_only: bool,
}

use crate::session_control::{
    isolation_control as control, isolation_inactive as inactive,
    isolation_successful as successful,
};

impl Registry {
    pub fn prepare<'a, E: Clone + RecordSource + 'a>(
        &mut self,
        records: impl Iterator<Item = (usize, &'a RecordedMysqlExchange<E>)>,
        scope: ReplaySource,
        case: Option<&str>,
    ) -> Vec<Plan> {
        if scope.is_run_owned() {
            for (_, record) in records {
                let Some(connection) = record.connection_id else {
                    continue;
                };
                if !record.sql.as_deref().is_some_and(crate::isolation::probe) {
                    continue;
                }
                if self.baselines.len() >= 4096 && !self.baselines.contains_key(&connection) {
                    self.exhausted = true;
                    continue;
                }
                let fact = (|| {
                    if !successful(record)
                        || record.command != "COM_QUERY"
                        || !inactive(record)
                        || record.response.status != "resultset"
                        || record.response.columns.len() != 1
                    {
                        return None;
                    }
                    // Construction only; no Source payload lookup occurs in live admission.
                    let response = record.response.materialize().ok()?;
                    let [row] = response.rows.as_slice() else {
                        return None;
                    };
                    let [value] = row.as_slice() else { return None };
                    if value.kind != "string" {
                        return None;
                    }
                    let value = value.value.as_ref()?.as_str()?;
                    Some(Baseline {
                        connection,
                        completed_at: record.timestamp,
                        identity: identity_from_exchange(record)?,
                        sequence: record.query_sequence?,
                        level: Level::reported(value)?,
                    })
                })();
                self.baselines
                    .entry(connection)
                    .and_modify(|prior| {
                        if prior.as_ref().zip(fact.as_ref()).is_none_or(|(a, b)| {
                            a.identity != b.identity
                                || a.level != b.level
                                || a.sequence == b.sequence
                        }) {
                            *prior = None;
                        }
                    })
                    .or_insert(fact);
                if self.baselines.get(&connection).is_some_and(Option::is_none)
                    && let Some(identity) = identity_from_exchange(record)
                    && !self.ambiguous_defaults.contains(&identity)
                    && self.ambiguous_defaults.len() < 4096
                {
                    self.ambiguous_defaults.push(identity);
                }
            }
            return Vec::new();
        }
        let Some(case) = case else { return Vec::new() };
        let mut connections = BTreeMap::<Uuid, Vec<(usize, &RecordedMysqlExchange<E>)>>::new();
        for (index, record) in records {
            if let Some(connection) = record.connection_id {
                connections
                    .entry(connection)
                    .or_default()
                    .push((index, record));
            }
        }
        let mut plans = Vec::new();
        for (connection, mut rows) in connections {
            let baseline = match self.baselines.get(&connection) {
                Some(fact) => fact.as_ref(),
                None => {
                    // Pools initialize their shared dialect on one connection;
                    // another connection inherits the same recorded resource default.
                    // Live admission requires unanimous facts, and prove() checks
                    // that this independent probe completed before this scope.
                    let identity = rows
                        .first()
                        .and_then(|(_, row)| identity_from_exchange(row));
                    self.baselines
                        .values()
                        .flatten()
                        .filter(|fact| {
                            Some(&fact.identity) == identity.as_ref() && fact.completed_at.is_some()
                        })
                        .min_by_key(|fact| fact.completed_at)
                }
            };
            let Some(baseline) = baseline else {
                continue;
            };
            rows.sort_by_key(|(_, row)| row.query_sequence);
            if rows
                .windows(2)
                .any(|r| r[0].1.query_sequence == r[1].1.query_sequence)
            {
                continue;
            }
            let mut reassertions = BTreeSet::new();
            for (start, &(index, row)) in rows.iter().enumerate() {
                if plans.len() >= 128 {
                    return plans;
                }
                let Some((Scope::Session, level)) =
                    row.sql.as_deref().and_then(crate::isolation::setting)
                else {
                    continue;
                };
                if reassertions.contains(&index) {
                    continue;
                }
                // Reasserting the known baseline has the same finite scope as
                // an override: prove the original transaction and restoration.
                if let Some(plan) = prove(case, connection, baseline, level, index, &rows[start..])
                {
                    reassertions.extend(plan.reassertions.iter().copied());
                    plans.push(plan);
                }
            }
        }
        plans
    }
}

fn prove<E>(
    case: &str,
    connection: Uuid,
    baseline: &Baseline,
    level: Level,
    setup: usize,
    rows: &[(usize, &RecordedMysqlExchange<E>)],
) -> Option<Plan> {
    let first = rows.first()?.1;
    let mut sequence = first.query_sequence?;
    if baseline
        .completed_at
        .zip(first.source_started_at())
        .is_some_and(|(probe, start)| probe > start)
    {
        return None;
    }
    let preceding = if baseline.connection == connection {
        baseline.sequence < sequence
    } else {
        baseline
            .completed_at
            .zip(first.source_started_at())
            .is_some_and(|(probe, start)| probe < start)
    };
    if !preceding
        || !control(first)
        || !inactive(first)
        || identity_from_exchange(first).as_ref() != Some(&baseline.identity)
    {
        return None;
    }
    let start_sequence = sequence;
    let mut previous = first.response.server_status?;
    let mut required = BTreeSet::new();
    let mut reassertions = BTreeSet::new();
    let mut read_only = true;
    let mut active = false;
    let mut end = None;
    let mut savepoints = crate::savepoint::Names::default();
    for &(index, row) in rows.iter().skip(1).take(260) {
        sequence = sequence.checked_add(1)?;
        let before = row.server_status_before? & 0x200b;
        let after = row.response.server_status? & 0x200b;
        if row.query_sequence != Some(sequence)
            || identity_from_exchange(row).as_ref() != Some(&baseline.identity)
            || before != previous & 0x200b
            || !successful(row)
        {
            return None;
        }
        previous = after;
        let sql = row.sql.as_deref()?;
        if let Some((Scope::Session, reset)) = crate::isolation::setting(sql) {
            // Pool initialization and a scoped checkout can reassert the same
            // level before any business operation. Keep these finite controls
            // until the Target genuinely covers the complete transaction.
            if reset == level && end.is_none() && required.is_empty() {
                if !control(row) || !inactive(row) || active {
                    return None;
                }
                reassertions.insert(index);
                continue;
            }
            if reset != baseline.level || !control(row) || !inactive(row) || active {
                return None;
            }
            return Some(Plan {
                identity: baseline.identity.clone(),
                case: case.into(),
                source_connection: connection,
                sequence: start_sequence,
                baseline_sequence: baseline.sequence,
                baseline_connection: baseline.connection,
                baseline: baseline.level,
                level,
                setup,
                end: end?,
                reset: index,
                reassertions,
                required,
                read_only,
            });
        }
        let normalized = normalize_sql(sql);
        if matches!(normalized.as_str(), "commit" | "rollback") {
            if !control(row) || after != 0 {
                return None;
            }
            if before == 1 && active && end.is_none() {
                active = false;
                end = Some(index);
                required.insert(index);
            } else if before != 0 || active {
                return None;
            }
            continue;
        }
        if let Some(savepoint) = crate::savepoint::parse(sql) {
            if !active
                || before != 1
                || after != 1
                || !control(row)
                || !savepoints.observe(&savepoint)
            {
                return None;
            }
            required.insert(index);
            continue;
        }
        // Exactly one implicit Source transaction. Session mutations,
        // failures, gaps and second transactions retain strict matching.
        let effect = optional_session::read::classify(sql);
        if end.is_some()
            || row.command != "COM_QUERY"
            || after != 1
            || !(before == 0 && !active || before == 1 && active)
            || effect == optional_session::read::Effect::Unknown
            || crate::sql::tokens(sql)
                .is_none_or(|t| optional_session::read::has_session_effect(&t))
            || !matches!(row.response.status.as_str(), "ok" | "resultset")
        {
            return None;
        }
        read_only &= effect == optional_session::read::Effect::ReadOnly;
        active = true;
        required.insert(index);
    }
    None
}
