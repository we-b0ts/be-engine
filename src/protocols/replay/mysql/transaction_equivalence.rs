//! Framework receipts and shared rules drive the native transaction constraints.
use super::*;
use traffic_protocol_mysql::transaction_delivery::ReadDelivery;
pub(crate) use traffic_protocol_mysql::transaction_delivery::{Delivery, Registry};
pub(super) type Witness =
    traffic_protocol_mysql::transaction_delivery::Witness<crate::dependency_index::RecordRef>;

impl ReplayState {
    pub(super) fn observe_mysql_transaction(
        &mut self,
        witness: &mut Witness,
        delivery: Delivery<'_>,
        read_delivery: Option<(&RecordedMysqlResponse, DateTime<Utc>, DateTime<Utc>)>,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
    ) {
        let command = delivery.command;
        let params = delivery.params;
        let sql = delivery.sql.to_owned();
        let prefix = self.prepare_mysql_prefix(witness, delivery, read_delivery, case);
        let exchanges = &self.protocols.mysql.exchanges;
        let observed = self
            .protocols
            .mysql
            .transaction_equivalence
            .observe_delivery_with_prefix(witness, delivery, prefix, |index| {
                matches!(
                    exchanges[index].status,
                    ReplayExchangeStatus::Responding | ReplayExchangeStatus::Consumed
                )
            });
        for (index, kind) in observed.omissions {
            if self.protocols.mysql.exchanges[index].status.is_available() {
                self.protocols.mysql.exchanges[index].optional_session = Some(kind);
                self.refresh_mysql_global_report(index);
            }
        }
        if let Some((index, reason)) = observed.violation {
            let source = self.protocols.mysql.exchanges[index].source;
            let diagnostic = self
                .protocols
                .mysql
                .transaction_equivalence
                .diagnostic(index);
            self.record_unmatched_in_case(
                case,
                identity,
                command,
                Some(&sql),
                params,
                &format!("MySQL transaction coverage: {reason}"),
            );
            if let Some(event) = self.protocols.mysql.events.unmatched_queries.last_mut() {
                event.recorded_source = Some(source);
                event.recorded_index = Some(index);
                event.diagnostic = diagnostic;
            }
        }
        let mysql = &mut self.protocols.mysql;
        if let Some(indices) = mysql.isolation.observe(
            witness.connection(),
            case,
            delivery,
            &mysql.transaction_equivalence,
            &SessionContext(&mysql.exchanges),
        ) {
            for index in indices {
                if self.protocols.mysql.exchanges[index].status.is_available() {
                    self.protocols.mysql.exchanges[index].optional_session =
                        Some(OptionalSessionExchange::TransactionIsolation);
                    self.refresh_mysql_global_report(index);
                }
            }
        }
    }

    fn prepare_mysql_prefix(
        &self,
        witness: &mut Witness,
        delivery: Delivery<'_>,
        wire: Option<(&RecordedMysqlResponse, DateTime<Utc>, DateTime<Utc>)>,
        case: Option<&str>,
    ) -> Option<usize> {
        self.protocols.mysql.transaction_equivalence.prepare_prefix(
            witness,
            delivery,
            wire,
            |index| {
                self.input_timing.as_ref()?.prefix_window(
                    case?,
                    self.protocols.mysql.exchanges[index]
                        .record
                        .request_started_at?,
                )
            },
            |expected, actual| {
                case.is_some_and(|case| {
                    self.mysql_prefix_response_matches(
                        &self.protocols.mysql.exchanges[expected].record,
                        actual,
                        case,
                    )
                })
            },
        )
    }

    fn mysql_prefix_response_matches(
        &self,
        expected: &RecordedMysqlExchange,
        actual: &ReadDelivery<crate::dependency_index::RecordRef>,
        case: &str,
    ) -> bool {
        let Ok(source) = expected.response.materialize() else {
            return false;
        };
        let Some((owner, policy)) = self.replay_policy.as_ref().and_then(|policy| {
            let owner = &policy.request_contracts;
            owner.compiled_rules().map(|policy| (owner, policy))
        }) else {
            return source == actual.response;
        };
        let clocks = owner.contract_clocks(
            Some(case),
            contracts::source_started(expected),
            Some(actual.requested_at),
            expected.timestamp,
            Some(actual.delivered_at),
        );
        contracts::automatic::compare_response(
            policy,
            &source,
            &actual.response,
            expected.sql.as_deref(),
            expected.database.as_deref(),
            clocks,
        )
        .is_ok_and(|result| result.passed())
    }
}
