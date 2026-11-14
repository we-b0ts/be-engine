//! Install native control facts while the framework retains live finite admission.
use super::*;
use crate::protocols::replay::source::DependencyRecord;
pub(in crate::replay) use traffic_protocol_mysql::session_control::ReadPrefixes;
pub(in crate::replay::mysql) use traffic_protocol_mysql::session_control::{
    successful_begin, successful_end,
};

impl MysqlReplayState {
    /// Reuse the native Source/Target proof without claiming consumption.
    /// A control Target has started must still finish its real delivery.
    pub(in crate::replay) fn permits_unstarted_omission(&self, index: usize) -> bool {
        self.exchanges.get(index).is_some_and(|exchange| {
            self.lifecycle
                .live_status(index, exchange.status)
                .is_available()
                && exchange.optional_session.is_some()
        })
    }

    /// A Source driver setup can depend on transaction coverage from later
    /// Socket.IO inputs. Defer that proof at dispatch only. The setup remains
    /// available and strict Target transaction checks still run at admission.
    pub(in crate::replay) fn can_defer_autocommit_for_dispatch(
        &self,
        index: usize,
        input_at: DateTime<Utc>,
    ) -> bool {
        self.exchanges.get(index).is_some_and(|exchange| {
            exchange.source == ReplaySource::Case
                && self
                    .lifecycle
                    .live_status(index, exchange.status)
                    .is_available()
                && exchange
                    .record
                    .sql
                    .as_deref()
                    .and_then(crate::mysql::autocommit::assignment)
                    == Some(false)
                && self
                    .transaction_equivalence
                    .can_defer_setup(index, input_at, |index| {
                        self.exchanges[index].record.request_started_at
                    })
        })
    }
}

pub(crate) fn classify(
    records: &[DependencyRecord],
    source: ReplaySource,
    global_prefixes: &mut ReadPrefixes,
) -> BTreeMap<usize, OptionalSessionExchange> {
    traffic_protocol_mysql::session_control::classify(
        super::source_records(records),
        source,
        global_prefixes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_control_classification_retains_original_positions_among_other_records() {
        let connection = Uuid::new_v4();
        let exchange = |sequence, sql| {
            serde_json::json!({
                "event_type": "mysql_exchange",
                "connection_id": connection,
                "query_sequence": sequence,
                "target_host": "db.internal",
                "target_port": 3306,
                "database": "app",
                "username": "user",
                "command": "COM_QUERY",
                "sql": sql,
                "response": {
                    "status": "ok",
                    "server_status": 0,
                    "affected_rows": 0,
                    "last_insert_id": 0
                }
            })
        };
        let records = [
            serde_json::json!({"event_type":"proxy_error","protocol":"http","error":"closed"}),
            exchange(1, "COMMIT"),
            serde_json::json!({"event_type":"proxy_error","protocol":"redis","error":"closed"}),
            exchange(2, "ROLLBACK"),
        ]
        .into_iter()
        .map(|value| serde_json::from_value(value).unwrap())
        .collect::<Vec<_>>();
        let optional = classify(
            &records,
            ReplaySource::Startup,
            &mut ReadPrefixes::default(),
        );
        assert_eq!(optional.len(), 1);
        assert_eq!(optional.get(&3), Some(&OptionalSessionExchange::Rollback));
    }
}
