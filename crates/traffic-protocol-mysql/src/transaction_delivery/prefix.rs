//! A finite read can provide the first member without selecting a locking transaction.
use super::*;
use crate::session_control as optional_session;
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
    target: &'a traffic_protocol::connection::Endpoint,
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
        context: &(impl SessionContext + ?Sized),
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
            if context.exchange(first).record.server_status_before != Some(0)
                || !source::locking_read::transaction_local(
                    context
                        .exchange(effect)
                        .record
                        .sql
                        .as_deref()
                        .unwrap_or_default(),
                )
                || normalize_sql(
                    context
                        .exchange(end)
                        .record
                        .sql
                        .as_deref()
                        .unwrap_or_default(),
                ) != "commit"
            {
                continue;
            }
            if let Some(key) = key(context.exchange(first))
                && optional_session::read::classify(key.sql)
                    == optional_session::read::Effect::ReadOnly
                && let Some(response) = recorded_fingerprint(context.exchange(first))
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
                let Some(key) = key(context.exchange(index)) else {
                    continue;
                };
                if let Some(responses) = locking.get(&key)
                    && let Some(response) = recorded_fingerprint(context.exchange(index))
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
    pub(super) fn confirmed<E>(
        &self,
        index: usize,
        actual: &RecordedMysqlResponse<E>,
    ) -> Option<usize> {
        let proof = self.slots.get(&index)?;
        self.raw_response_matches(proof.group, actual)
            .then_some(proof.group)
    }

    #[cfg(test)]
    fn raw_response_matches<E>(&self, group: usize, actual: &RecordedMysqlResponse<E>) -> bool {
        fingerprint(actual) == Some(self.groups[&group].response)
    }

    pub(super) fn covers(&self, expected: usize, group: Option<usize>) -> bool {
        self.slots
            .get(&expected)
            .is_some_and(|proof| proof.locking && group == Some(proof.group))
    }
}

fn key<E>(exchange: SourceExchange<'_, E>) -> Option<Key<'_>> {
    let record = exchange.record;
    let case = exchange.case_id?;
    let sql = record.sql.as_deref()?;
    if exchange.source != ReplaySource::Case
        || exchange.optional_session.is_some()
        || record.lifecycle_cleanup
        || record.command != "COM_QUERY"
        || record.outcome != traffic_model::DependencyExchangeOutcome::Response
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
            !matches!(capture.attribution, traffic_model::attribution::DependencyOwner::Case { origin_case_id, .. }
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

fn recorded_fingerprint<E: Clone + RecordSource>(
    exchange: SourceExchange<'_, E>,
) -> Option<[u8; 32]> {
    let response = &exchange.record.response;
    if response.evidence.as_ref().is_some_and(|evidence| {
        evidence
            .byte_len()
            .is_none_or(|length| length > MAX_BYTES as u64)
    }) {
        return None;
    }
    fingerprint(&response.materialize().ok()?)
}

fn fingerprint<E>(response: &RecordedMysqlResponse<E>) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(response).ok()?;
    (bytes.len() <= MAX_BYTES).then(|| Sha256::digest(bytes).into())
}

impl Registry {
    pub fn prepare_prefix<E: Clone>(
        &self,
        witness: &mut Witness<E>,
        delivery: Delivery<'_>,
        wire: Option<(&RecordedMysqlResponse<E>, DateTime<Utc>, DateTime<Utc>)>,
        window: impl Fn(usize) -> Option<(usize, usize)>,
        response_matches: impl Fn(usize, &ReadDelivery<E>) -> bool,
    ) -> Option<usize> {
        let previous = witness.first_delivery.take();
        let index = delivery.index?;
        if let Some(previous) = previous {
            let trace = witness.active.as_mut()?;
            let actual = *trace.members.first()?;
            let &(requirement, transaction) = self.members.get(&index)?;
            let group = &self.requirements[requirement].transactions[transaction];
            if let [expected, effect, _] = group.members.as_slice()
                && *effect == index
                && *expected != actual
                && self.prefixes.covers(*expected, trace.neutral_first)
                && window(actual).is_some_and(|actual| window(*expected) == Some(actual))
                && response_matches(*expected, &previous)
            {
                trace.prefix_equivalent = true;
                tracing::debug!(
                    actual,
                    expected,
                    index,
                    "confirmed equivalent MySQL first read after locking statement"
                );
            }
            return None;
        }
        if !delivery.successful
            || delivery.after & 1 == 0
            || !witness
                .active
                .as_ref()
                .map_or(delivery.before & 1 == 0, |trace| {
                    trace.valid && trace.members.is_empty() && !trace.skipped_free_read
                })
        {
            return None;
        }
        let (response, requested_at, delivered_at) = wire?;
        let group = self.prefixes.group_in_window(index, window)?;
        witness.first_delivery = Some(ReadDelivery {
            response: response.clone(),
            requested_at,
            delivered_at,
        });
        Some(group)
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    #[derive(Clone)]
    struct Evidence {
        length: Option<u64>,
        reads: Rc<Cell<usize>>,
        envelope: Value,
    }

    impl RecordSource for Evidence {
        fn load<T: serde::de::DeserializeOwned>(&self) -> anyhow::Result<T> {
            self.reads.set(self.reads.get() + 1);
            Ok(serde_json::from_value(self.envelope.clone())?)
        }

        fn byte_len(&self) -> Option<u64> {
            self.length
        }
    }

    #[test]
    fn native_prefix_checks_the_hosts_evidence_bound_before_materializing() {
        for (length, expected_reads) in [
            (None, 0),
            (Some(MAX_BYTES as u64 + 1), 0),
            (Some(MAX_BYTES as u64), 1),
        ] {
            let envelope = super::super::test_support::records()[1].clone();
            let mut record: RecordedMysqlExchange<Evidence> =
                serde_json::from_value(envelope.clone()).unwrap();
            let expected = fingerprint(&record.response).unwrap();
            let identity = crate::session_identity::identity_from_exchange(&record).unwrap();
            let reads = Rc::new(Cell::new(0));
            record.response.detach(Evidence {
                length,
                reads: reads.clone(),
                envelope,
            });
            let actual = recorded_fingerprint(SourceExchange {
                record: &record,
                identity: &identity,
                source: ReplaySource::Case,
                case_id: Some("case"),
                optional_session: None,
            });
            assert_eq!(actual, (expected_reads == 1).then_some(expected));
            assert_eq!(reads.get(), expected_reads);
        }
    }
}
