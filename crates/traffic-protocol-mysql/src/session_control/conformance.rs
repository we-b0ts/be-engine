//! Native Source safety contracts run independently of the Replay application.
use super::{OptionalSessionExchange, ReadPrefixes, read};
use crate::recorded::RecordedMysqlExchange;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use traffic_model::attribution::DependencyScope as ReplaySource;
use uuid::Uuid;

type DependencyRecord = RecordedMysqlExchange;

fn classify(
    records: &[DependencyRecord],
    source: ReplaySource,
    prefixes: &mut ReadPrefixes,
) -> BTreeMap<usize, OptionalSessionExchange> {
    super::classify(records.iter().enumerate(), source, prefixes)
}

mod autocommit;
mod tests;
