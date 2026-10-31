//! Install proven Case records as finite Global exchanges before Target admission.
//! Native Global report slots remain stable; projections are session extras.
use super::*;

#[derive(Debug, Serialize)]
pub(in crate::replay) struct GlobalTransactionExchange {
    #[serde(flatten)]
    pub exchange: RecordedExchangeSummary,
    #[serde(flatten)]
    pub provenance: transaction_ownership::Provenance,
}

impl MysqlReplayState {
    pub(in crate::replay) fn install_global_transactions(
        &mut self,
        prepared: transaction_ownership::Prepared,
        targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    ) -> Result<()> {
        self.transaction_wires = prepared.wires;
        for promoted in prepared.promoted {
            let record = promoted.record;
            let identity = identity_from_exchange(&record)
                .context("proven Global transaction member lacks MySQL resource identity")?;
            register_replay_target(targets, &identity.target, ReplayProtocol::Mysql)?;
            let wire = record
                .connection_id
                .zip(record.query_sequence)
                .context("proven Global transaction member lacks wire identity")?;
            self.promoted_wires.insert(wire);
            if record.command == "COM_PING"
                || record.command == "COM_STMT_PREPARE"
                || crate::mysql::wire::is_no_response_command(&record.command)
            {
                continue;
            }
            let timing = ReplayExchangeTiming::from_recorded(record.duration_ms, record.outcome);
            let index = self.exchanges.len();
            self.register_exchange(ReplayExchange {
                source: promoted.source,
                case_id: None,
                identity,
                record,
                optional_session: None,
                status: ReplayExchangeStatus::Available,
                timing,
            });
            self.transaction_provenance
                .insert(index, promoted.provenance);
        }
        tracing::info!(
            promoted = self.transaction_provenance.len(),
            cache_reused = prepared.cache_reused,
            source_bytes = prepared.source_bytes,
            "prepared Global MySQL transaction ownership"
        );
        Ok(())
    }
}

impl ReplayState {
    pub(in crate::replay) fn global_mysql_transactions(&self) -> Vec<GlobalTransactionExchange> {
        self.mysql
            .transaction_provenance
            .iter()
            .map(|(index, provenance)| GlobalTransactionExchange {
                exchange: self.mysql_summary(*index),
                provenance: provenance.clone(),
            })
            .collect()
    }
}
