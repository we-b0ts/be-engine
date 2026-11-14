//! Native Source facts retain their original indexes for framework installation.
use super::*;
use crate::replay::dependencies::DependencyRecord;
pub(super) use traffic_protocol_mysql::transaction_source::locking_read;
pub(in crate::replay) use traffic_protocol_mysql::transaction_source::{
    Plan, RejectedEnd, requires_source_setup, update_outcome,
};

pub(super) fn prepare(
    records: &[DependencyRecord],
    optional: &BTreeMap<usize, OptionalSessionExchange>,
    scope: ReplaySource,
    global_reads: &source_evidence::GlobalReads,
) -> Vec<Plan> {
    traffic_protocol_mysql::transaction_source::prepare(
        super::super::source_records(records),
        optional,
        scope,
        global_reads,
    )
}
