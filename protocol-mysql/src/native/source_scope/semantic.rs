//! Derive transaction requirements from complete Source execution evidence.
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::{
    DriverPrelude, Endpoint, EventSessionPreparation, ReplaySessionStep,
};

use super::ScopeRecord;
use crate::{
    recorded::RecordedMysqlExchange,
    session_control::{SourceControl, successful_begin, successful_end},
    session_identity::target_from_exchange,
    transaction_source::{Segment, update_outcome},
};

const ORDINARY_STATUS_BITS: u16 = 1 | 2 | 16 | 32 | 2048;

pub(super) struct Scope<'a> {
    records: &'a BTreeMap<usize, &'a ScopeRecord>,
    admissions: BTreeMap<u64, bool>,
}

impl<'a> Scope<'a> {
    pub(super) fn new(records: &'a BTreeMap<usize, &'a ScopeRecord>) -> Self {
        let ordered: BTreeMap<_, _> = records
            .values()
            .filter_map(|&record| {
                let capture = record.exchange.capture.as_ref()?;
                capture
                    .semantic_required
                    .then_some((capture.sequence, (record, capture.started_at)))
            })
            .collect();
        // An UPDATE cannot move its commit across an earlier request that
        // might still observe this endpoint. Keep just the maximum known
        // completion for each endpoint while walking the admission order.
        let mut latest = BTreeMap::<Endpoint, Option<chrono::DateTime<chrono::Utc>>>::new();
        let admissions = ordered
            .into_iter()
            .map(|(sequence, (record, captured_start))| {
                let exchange = &record.exchange;
                let clear = target_from_exchange(exchange).is_some_and(|endpoint| {
                    let start = exchange.request_started_at.unwrap_or(captured_start);
                    let clear = latest.get(&endpoint).is_none_or(|completion| {
                        completion.is_some_and(|completion| completion <= start)
                    });
                    if !successful_begin(exchange) {
                        let completion = exchange
                            .timestamp
                            .filter(|&end| record.complete && end >= start);
                        latest
                            .entry(endpoint)
                            .and_modify(|previous| {
                                *previous = previous.zip(completion).map(|(a, b)| a.max(b));
                            })
                            .or_insert(completion);
                    }
                    clear
                });
                (sequence, clear)
            })
            .collect();
        Self {
            records,
            admissions,
        }
    }

    pub(super) fn project(
        &self,
        segment: &Segment,
        controls: &BTreeMap<usize, SourceControl>,
        result: &mut EventSessionPreparation,
    ) -> bool {
        let begin = segment
            .members
            .first()
            .copied()
            .filter(|_| segment.explicit);
        let end = *segment.members.last().expect("proved terminal");
        if begin.is_some_and(|index| {
            controls.get(&index) != Some(&SourceControl::BeginMode) || !self.clean_control(index)
        }) || !self.clean_control(end)
            || !segment.members.iter().all(|index| {
                let record = self.records[index];
                record.complete
                    && record
                        .exchange
                        .server_status_before
                        .zip(record.exchange.response.server_status)
                        .is_some_and(|(before, after)| {
                            (before | after) & !ORDINARY_STATUS_BITS == 0
                        })
            })
        {
            return false;
        }

        if let Some(first_write) = segment.first_write {
            self.project_write_span(segment, first_write, begin, result);
        } else if controls.get(&end) == Some(&SourceControl::ReadOnlyEnd) {
            for index in &segment.members {
                result.steps.remove(index);
            }
            result
                .driver_prelude
                .insert(end, DriverPrelude::MysqlReadOnlyTransactionEnd);
        } else {
            return false;
        }
        if let Some(begin) = begin {
            result
                .driver_prelude
                .insert(begin, DriverPrelude::MysqlTransactionBegin);
        }
        true
    }

    fn project_write_span(
        &self,
        segment: &Segment,
        first_write: usize,
        begin: Option<usize>,
        result: &mut EventSessionPreparation,
    ) {
        for index in &segment.members[..first_write] {
            result.steps.remove(index);
        }
        let members = &segment.members[first_write..];
        let first = members[0];
        // Only BEGIN and the single write may precede COMMIT. In particular,
        // a mixed read/write span keeps its writable transaction tail.
        let autocommit = if let [write, commit] = members
            && first_write == usize::from(begin.is_some())
        {
            self.autocommit_equivalent(*write, *commit)
        } else {
            false
        };
        result.steps.insert(
            first,
            if autocommit {
                ReplaySessionStep::AutocommitWrite
            } else {
                ReplaySessionStep::Start
            },
        );
        for (position, pair) in members.windows(2).enumerate() {
            let after = reference(&self.records[&pair[0]].exchange);
            let step = if autocommit {
                ReplaySessionStep::AutocommitCommit { after }
            } else {
                ReplaySessionStep::Continue {
                    after,
                    end: position + 2 == members.len(),
                }
            };
            result.steps.insert(pair[1], step);
        }
    }

    fn clean_control(&self, index: usize) -> bool {
        let record = &self.records[&index].exchange;
        !record.lifecycle_cleanup
            && record.response.wire_prefix.is_empty()
            && record.capture.as_ref().is_some_and(|capture| {
                capture.semantic_required
                    && capture.sequence > 0
                    && capture.protocol_ref == reference(record)
                    && capture.transformations.is_empty()
                    && capture.effect_index == 0
            })
    }

    fn autocommit_equivalent(&self, write: usize, commit: usize) -> bool {
        let write = &self.records[&write].exchange;
        let commit = &self.records[&commit].exchange;
        matches!(
            update_outcome(write),
            Some("positive_affected_rows" | "zero_affected_rows")
        ) && !write.lifecycle_cleanup
            && write.response.wire_prefix.is_empty()
            && successful_end(commit, &["commit"])
            && commit.params.is_none()
            && write.query_sequence.and_then(|seq| seq.checked_add(1)) == commit.query_sequence
            && write
                .capture
                .as_ref()
                .zip(commit.capture.as_ref())
                .is_some_and(|(write_capture, commit_capture)| {
                    write_capture.semantic_required
                        && write_capture.transformations.is_empty()
                        && write_capture.effect_index == 0
                        && write_capture.protocol_ref == reference(write)
                        && write_capture.process_epoch == commit_capture.process_epoch
                        && self.admissions.get(&write_capture.sequence) == Some(&true)
                        && self
                            .admissions
                            .range((Excluded(write_capture.sequence), Unbounded))
                            .next()
                            .is_some_and(|(&next, _)| next == commit_capture.sequence)
                })
    }
}

fn reference(record: &RecordedMysqlExchange) -> ProtocolRef {
    ProtocolRef::connection(
        "mysql",
        record.connection_id.expect("proved Source connection"),
        record.query_sequence.expect("proved Source sequence"),
    )
}
