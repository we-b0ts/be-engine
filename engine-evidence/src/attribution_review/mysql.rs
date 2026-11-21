//! MySQL transaction evidence for the unattributed projection.
use super::{GroupShape, grouping::mysql_selectors};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use traffic_model::{attribution::DependencyScope, recording::ProtocolRef};
use traffic_protocol::{evidence::EvidenceRegistry, observation::format_endpoint};
use traffic_protocol_mysql::{
    recorded::RecordedMysqlExchange,
    session_control::{SourceControl, prepare_source_transactions},
    session_identity::identity_from_exchange,
    transaction_source::{GlobalReads, Plan},
};
use uuid::Uuid;

#[derive(Default)]
pub(super) struct Source {
    records: Vec<RecordedMysqlExchange>,
    incomplete_connections: BTreeSet<Uuid>,
}

impl Source {
    pub(super) fn observe(&mut self, mut event: Value, evidence: &EvidenceRegistry) {
        if event["event_type"] != "mysql_exchange" {
            return;
        }
        let connection = event["connection_id"]
            .as_str()
            .and_then(|id| id.parse::<Uuid>().ok());
        let response = &event["response"];
        let complete = evidence.supports_replay(&event)
            && evidence.capture_complete(&event)
            && (response["status"] != "resultset" || response["rows"].is_array());
        let row_shape = response["rows"].as_array().map(|rows| {
            let columns = response["columns"].as_array().map_or(0, Vec::len);
            (
                rows.len(),
                rows.iter()
                    .all(|row| row.as_array().is_some_and(|row| row.len() == columns)),
            )
        });
        // The proof needs result shape and parameter presence. Neither row
        // values nor wire prefix packets participate in the control proof.
        if let Some(response) = event["response"].as_object_mut() {
            response.remove("rows");
            response.remove("wire_prefix");
        }
        if let Ok(mut record) = serde_json::from_value::<RecordedMysqlExchange>(event)
            && complete
            && record.capture.as_ref().is_some_and(|capture| {
                record
                    .connection_id
                    .zip(record.query_sequence)
                    .is_some_and(|(id, seq)| {
                        capture.protocol_ref == ProtocolRef::connection("mysql", id, seq)
                    })
            })
        {
            record.response.row_shape = row_shape;
            self.records.push(record);
        } else if let Some(connection) = connection {
            self.incomplete_connections.insert(connection);
        }
    }

    fn valid_records(&self) -> impl Iterator<Item = (usize, &RecordedMysqlExchange)> + Clone {
        self.records.iter().enumerate().filter(|(_, record)| {
            record
                .connection_id
                .is_some_and(|id| !self.incomplete_connections.contains(&id))
        })
    }

    pub(super) fn optional_controls(&self) -> BTreeSet<Uuid> {
        self.plan()
            .0
            .into_keys()
            .filter_map(|index| {
                self.records[index]
                    .capture
                    .as_ref()
                    .filter(|capture| super::needs_review(capture))
                    .map(|capture| capture.exchange_id)
            })
            .collect()
    }

    fn exchange_id(&self, index: usize) -> Option<Uuid> {
        self.records[index]
            .capture
            .as_ref()
            .map(|capture| capture.exchange_id)
    }

    fn plan(&self) -> (BTreeMap<usize, SourceControl>, Vec<Plan>) {
        prepare_source_transactions(
            self.valid_records(),
            DependencyScope::Unattributed,
            &GlobalReads::default(),
        )
    }

    pub(super) fn transaction_shapes(
        &self,
        pending: &BTreeSet<Uuid>,
    ) -> BTreeMap<Uuid, Arc<GroupShape>> {
        let mut groups = BTreeMap::new();
        for plan in self.plan().1 {
            for segment in plan.transactions {
                let ids: Vec<_> = segment
                    .members
                    .iter()
                    .filter_map(|&index| self.exchange_id(index).filter(|id| pending.contains(id)))
                    .collect();
                if ids.len() < 2 {
                    continue;
                }
                let first = &self.records[segment.members[0]];
                let database = first.database.clone();
                let shape = Arc::new(GroupShape {
                    protocol: "mysql".into(),
                    endpoint: identity_from_exchange(first).map(|identity| {
                        format_endpoint(&identity.target.host, identity.target.port)
                    }),
                    database,
                    operation: "transaction".into(),
                    selectors: segment
                        .members
                        .iter()
                        .flat_map(|&index| {
                            let record = &self.records[index];
                            record
                                .sql
                                .as_deref()
                                .map(|sql| mysql_selectors(sql, record.database.as_deref()))
                                .unwrap_or_else(|| vec![record.command.clone()])
                        })
                        .collect(),
                    selector_count: None,
                });
                for id in ids {
                    groups.insert(id, Arc::clone(&shape));
                }
            }
        }
        groups
    }
}
