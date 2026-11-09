//! A finite read can provide the first member without selecting a locking transaction.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
pub(super) struct Index {
    slots: BTreeMap<usize, Proof>,
    groups: BTreeMap<usize, Group>,
}

#[derive(Debug, Clone, Copy)]
struct Proof {
    group: usize,
    locking: bool,
}

#[derive(Debug)]
struct Group {
    locking: Vec<usize>,
    ordinary: Vec<usize>,
    #[cfg(test)]
    response: [u8; 32],
}

#[derive(Hash, PartialEq, Eq)]
struct Key<'a> {
    case: &'a str,
    target: &'a TargetKey,
    database: Option<&'a str>,
    username: Option<&'a str>,
    sql: &'a str,
    duration_ms: u64,
}

impl Index {
    pub(super) fn register(
        &mut self,
        plans: &[source::Plan],
        mapping: &BTreeMap<usize, usize>,
        exchanges: &[ReplayExchange],
    ) {
        let mut locking = HashMap::new();
        for segment in plans.iter().flat_map(|plan| &plan.transactions) {
            let [first, effect, end] = segment.members.as_slice() else {
                continue;
            };
            if segment.explicit || segment.write_count != 0 || !segment.strict {
                continue;
            }
            let (Some(&first), Some(&effect), Some(&end)) =
                (mapping.get(first), mapping.get(effect), mapping.get(end))
            else {
                continue;
            };
            if exchanges[first].record.server_status_before != Some(0)
                || !source::locking_read::transaction_local(
                    exchanges[effect].record.sql.as_deref().unwrap_or_default(),
                )
                || normalize_sql(exchanges[end].record.sql.as_deref().unwrap_or_default())
                    != "commit"
            {
                continue;
            }
            if let Some(key) = key(&exchanges[first])
                && optional_session::read::classify(key.sql)
                    == optional_session::read::Effect::ReadOnly
                && let Some(response) = recorded_fingerprint(&exchanges[first])
            {
                locking
                    .entry(key)
                    .or_insert_with(HashMap::new)
                    .entry(response)
                    .or_insert_with(Vec::new)
                    .push(first);
            }
        }
        if locking.is_empty() {
            return;
        }
        let mut ordinary = HashMap::new();
        for segment in plans.iter().flat_map(|plan| &plan.transactions) {
            if segment.explicit
                || segment.strict
                || segment.write_count != 0
                || segment
                    .members
                    .iter()
                    .any(|index| !mapping.contains_key(index))
            {
                continue;
            }
            for &member in &segment.members {
                let index = mapping[&member];
                let Some(key) = key(&exchanges[index]) else {
                    continue;
                };
                if let Some(responses) = locking.get(&key)
                    && let Some(response) = recorded_fingerprint(&exchanges[index])
                    && responses.contains_key(&response)
                {
                    ordinary
                        .entry((key, response))
                        .or_insert_with(Vec::new)
                        .push(index);
                }
            }
        }
        for ((key, response), ordinary) in ordinary {
            let locking = locking[&key][&response].clone();
            let group = locking[0];
            for &index in &locking {
                self.slots.insert(
                    index,
                    Proof {
                        group,
                        locking: true,
                    },
                );
            }
            for &index in &ordinary {
                self.slots.insert(
                    index,
                    Proof {
                        group,
                        locking: false,
                    },
                );
            }
            self.groups.insert(
                group,
                Group {
                    locking,
                    ordinary,
                    #[cfg(test)]
                    response,
                },
            );
        }
    }

    pub(super) fn group_in_window(
        &self,
        index: usize,
        window: impl Fn(usize) -> Option<(usize, usize)>,
    ) -> Option<usize> {
        let proof = self.slots.get(&index)?;
        let at = window(index)?;
        let group = &self.groups[&proof.group];
        let others = if proof.locking {
            &group.ordinary
        } else {
            &group.locking
        };
        others
            .iter()
            .any(|&other| window(other) == Some(at))
            .then_some(proof.group)
    }

    #[cfg(test)]
    pub(super) fn confirmed(&self, index: usize, actual: &RecordedMysqlResponse) -> Option<usize> {
        let proof = self.slots.get(&index)?;
        self.raw_response_matches(proof.group, actual)
            .then_some(proof.group)
    }

    #[cfg(test)]
    fn raw_response_matches(&self, group: usize, actual: &RecordedMysqlResponse) -> bool {
        fingerprint(actual) == Some(self.groups[&group].response)
    }

    pub(super) fn covers(&self, expected: usize, group: Option<usize>) -> bool {
        self.slots
            .get(&expected)
            .is_some_and(|proof| proof.locking && group == Some(proof.group))
    }
}

fn key(exchange: &ReplayExchange) -> Option<Key<'_>> {
    let record = &exchange.record;
    let case = exchange.case_id.as_deref()?;
    let sql = record.sql.as_deref()?;
    if exchange.source != ReplaySource::Case
        || exchange.optional_session.is_some()
        || record.lifecycle_cleanup
        || record.command != "COM_QUERY"
        || record.outcome != crate::DependencyExchangeOutcome::Response
        || record
            .params
            .as_ref()
            .is_some_and(|params| !params.is_empty())
        || record.result_row_count().is_none_or(|rows| rows > 16)
        || record.response.columns.len() > 32
        || !record.response.wire_prefix.is_empty()
        || !matches!(record.server_status_before, Some(0 | 1))
        || record.response.server_status != Some(1)
        || record.capture.as_ref().is_some_and(|capture| {
            !matches!(capture.attribution, crate::DependencyOwner::Case { origin_case_id, .. }
                if Uuid::parse_str(case).ok() == Some(origin_case_id))
        })
    {
        return None;
    }
    Some(Key {
        case,
        target: &exchange.identity.target,
        database: exchange.identity.database.as_deref(),
        username: exchange.identity.username.as_deref(),
        sql,
        duration_ms: record.duration_ms,
    })
}

fn recorded_fingerprint(exchange: &ReplayExchange) -> Option<[u8; 32]> {
    let response = &exchange.record.response;
    if response
        .evidence
        .as_ref()
        .is_some_and(|evidence| evidence.location.length > MAX_BYTES as u64)
    {
        return None;
    }
    fingerprint(&response.materialize().ok()?)
}

fn fingerprint(response: &RecordedMysqlResponse) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(response).ok()?;
    (bytes.len() <= MAX_BYTES).then(|| Sha256::digest(bytes).into())
}
