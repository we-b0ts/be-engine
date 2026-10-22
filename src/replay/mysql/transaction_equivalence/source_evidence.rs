//! Immutable Global read facts may complete a Case's pre-write Source proof.
//! These facts never match or consume a replay exchange.
use super::*;
use crate::replay::dependencies::DependencyRecord;

#[derive(Debug, Default)]
pub(super) struct GlobalReads(BTreeMap<(Uuid, u64), Option<ReadFact>>);

#[derive(Debug)]
struct ReadFact {
    identity: MysqlDependencyIdentity,
    before: u16,
    after: u16,
}

impl GlobalReads {
    pub(super) fn contains_wire(&self, record: &RecordedMysqlExchange) -> bool {
        record
            .connection_id
            .zip(record.query_sequence)
            .is_some_and(|wire| self.0.contains_key(&wire))
    }

    pub(super) fn record(&mut self, records: &[DependencyRecord]) {
        for record in records {
            let DependencyRecord::MysqlExchange(record) = record else {
                continue;
            };
            let Some(wire) = record.connection_id.zip(record.query_sequence) else {
                continue;
            };
            let fact = (|| {
                if !optional_session::complete_read(record)
                    || optional_session::read::classify(record.sql.as_deref()?)
                        != optional_session::read::Effect::ReadOnly
                {
                    return None;
                }
                Some(ReadFact {
                    identity: identity_from_exchange(record)?,
                    before: record.server_status_before?,
                    after: record.response.server_status?,
                })
            })();
            self.0
                .entry(wire)
                .and_modify(|existing| *existing = None)
                .or_insert(fact);
        }
    }

    pub(super) fn bridges(
        &self,
        connection: Uuid,
        identity: &MysqlDependencyIdentity,
        last: u64,
        next: u64,
        mut status: u16,
        before: u16,
    ) -> bool {
        let Some(mut expected) = last.checked_add(1).filter(|first| *first < next) else {
            return false;
        };
        // Iteration is bounded by actual immutable facts, never a numeric gap.
        for (&(_, sequence), fact) in self.0.range((connection, expected)..(connection, next)) {
            let Some(fact) = fact else {
                return false;
            };
            if sequence != expected
                || fact.identity != *identity
                || fact.before & 0x200b != status & 0x200b
                || fact.after & 0x2009 != 1
                || fact.before & 2 != fact.after & 2
            {
                return false;
            }
            status = fact.after;
            expected = sequence + 1;
        }
        expected == next && status & 0x200b == before & 0x200b
    }
}
