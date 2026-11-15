//! Native report paths project immutable capture identities into shared publication.
use super::*;
use crate::replay::report::unused_source::{SourceIdentity, SourceRow};
use serde_json::Value;
use traffic_replay::ReplaySource;
use uuid::Uuid;

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

    fn exchange_id(
        self,
        state: &RuntimeState<ReplayProtocols>,
        case: &str,
        row: &Value,
    ) -> Option<Uuid> {
        if matches!(self, Self::Redis) && row["command"] == "PUBSUB_PUSH" {
            return explicit_exchange_id(row)?.parse().ok();
        }
        let index = usize::try_from(row["index"].as_u64()?).ok()?;
        match self {
            Self::Mysql => {
                let exchange = state.protocol_data().mysql.exchanges.get(index)?;
                if !exchange.source.matches_scope(ReplaySource::Case)
                    || exchange.case_id.as_deref() != Some(case)
                {
                    return None;
                }
                Some(exchange.record.capture.as_ref()?.exchange_id)
            }
            Self::Redis => state.protocol_data().redis.case_exchange_id(case, index),
        }
    }
}

fn explicit_exchange_id(row: &Value) -> Option<&str> {
    row["source_exchange_id"]
        .as_str()
        .or_else(|| row["capture"]["exchange_id"].as_str())
}

pub(in crate::protocols::replay) fn rows(
    state: &RuntimeState<ReplayProtocols>,
    report: &Value,
) -> Vec<SourceRow> {
    let mut rows = Vec::new();
    for section in [Section::Mysql, Section::Redis] {
        for (position, row) in section
            .rows(report)
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let Some(case) = row["case_id"].as_str() else {
                continue;
            };
            let Some(exchange_id) = section.exchange_id(state, case, row) else {
                continue;
            };
            let (path, event_type) = match section {
                Section::Mysql => ("/unused_case_exchanges", "mysql_exchange"),
                Section::Redis if row["command"] == "PUBSUB_PUSH" => {
                    ("/redis/unused_case", "redis_pub_sub_push")
                }
                Section::Redis => ("/redis/unused_case", "redis_exchange"),
            };
            rows.push(SourceRow {
                pointer: format!("{path}/{position}"),
                case: case.into(),
                exchange_id,
                identity: SourceIdentity::EventType(event_type),
            });
        }
    }
    rows
}
