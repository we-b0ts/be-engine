//! Native session preparation projected into immutable framework memberships.
use super::*;
use crate::policy::runtime::RequestContracts;
use crate::replay::{PreparedProtocol, RunSequenceReference};

impl MysqlReplayState {
    pub(crate) fn prepare_case(
        &mut self,
        case: &str,
        contracts: Option<&RequestContracts>,
    ) -> Result<PreparedProtocol> {
        let members = self.prepared_case_members(case);
        if let Some(contracts) = contracts {
            self.prepare_request_sources(contracts, case, &members)?;
        }
        let exempt: Vec<_> = members
            .iter()
            .copied()
            .filter(|index| self.recorded_sequence(*index).is_none())
            .collect();
        self.prepare_sequence_exempt(exempt.into_iter());
        let sequence = members
            .iter()
            .filter_map(|index| Some((*index, self.recorded_sequence(*index)?)))
            .collect::<Vec<_>>()
            .into();
        Ok(PreparedProtocol { members, sequence })
    }

    pub(crate) fn prepare_run_sequence(&mut self) -> Result<Vec<RunSequenceReference>> {
        let exempt: Vec<_> = self
            .exchanges
            .iter()
            .enumerate()
            .filter(|(index, exchange)| {
                exchange.source.is_run_owned() && self.recorded_sequence(*index).is_none()
            })
            .map(|(index, _)| index)
            .collect();
        self.prepare_sequence_exempt(exempt.into_iter());
        self.exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source.is_run_owned())
            .filter_map(|(index, exchange)| {
                let sequence = self.recorded_sequence(index)?;
                Some((|| {
                    Ok(RunSequenceReference {
                        index,
                        sequence,
                        owner: exchange
                            .record
                            .capture
                            .as_ref()
                            .context("MySQL run dependency owner absent")?
                            .attribution
                            .clone(),
                    })
                })())
            })
            .collect()
    }
}

impl MysqlReplayState {
    pub(crate) fn case_in_flight_diagnostic(&self) -> serde_json::Value {
        let pending = self
            .exchanges
            .iter()
            .enumerate()
            .filter(|(index, exchange)| {
                exchange.source == ReplaySource::Case
                    && matches!(
                        self.exchange_status(*index),
                        Some(
                            ReplayExchangeStatus::Responding
                                | ReplayExchangeStatus::AwaitingClientTermination
                        )
                    )
            });
        let count = pending.clone().count();
        let references = pending.take(4).map(|(index, exchange)| serde_json::json!({
            "index": index, "case_id": exchange.case_id,
            "connection_id": exchange.record.connection_id, "query_sequence": exchange.record.query_sequence,
            "status": format!("{:?}", exchange.status)
        })).collect::<Vec<_>>();
        serde_json::json!({"count": count, "references": references, "omitted": count.saturating_sub(4)})
    }
}
