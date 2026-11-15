//! Source ownership is prepared before Target admission and looked up only in memory.
use super::*;
use crate::api_trigger::OriginIndex;

#[derive(Debug)]
pub(super) struct Owner {
    rule: String,
    trigger_case_id: String,
}

type WireProofs = BTreeMap<String, Arc<Owner>>;
pub(super) type Origins = Arc<BTreeMap<(Uuid, u64), WireProofs>>;

#[derive(Debug, Serialize)]
pub(crate) struct OwnedExchange {
    #[serde(flatten)]
    pub exchange: RecordedExchangeSummary,
    pub ownership_rule: String,
    pub trigger_case_id: String,
}

pub(crate) fn load(
    source: &Path,
    rules: &[crate::BackgroundDependencyRuleConfig],
) -> Result<OriginIndex> {
    // Effective ownership is frozen from the independent attribution overlay.
    // A native request selector is not authority to exempt another Case.
    let _ = (source, rules);
    Ok(OriginIndex::default())
}

impl MysqlReplayState {
    pub(crate) fn set_origins(&mut self, origins: OriginIndex, selected: &BTreeSet<String>) {
        let cache_reused = origins.cache_reused;
        let source_bytes = origins.source_bytes;
        // Drop full-recording witnesses, private identities and file paths before
        // Target startup. Deferred cases need only their compact immutable keys.
        let mut compact = BTreeMap::<(Uuid, u64), WireProofs>::new();
        for (wire, key, owner) in origins
            .wire_witnesses
            .into_iter()
            .filter_map(|(key, witness)| {
                let case = witness.dependencies_path.parent()?.file_name()?.to_str()?;
                if witness.same_resource_read || !selected.contains(case) {
                    return None;
                }
                let (prefix, sequence) = key.rsplit_once('/')?;
                let (_, connection) = prefix.rsplit_once('/')?;
                let wire = (connection.parse().ok()?, sequence.parse().ok()?);
                Some((
                    wire,
                    key,
                    Arc::new(Owner {
                        rule: witness.rule,
                        trigger_case_id: witness.trigger_case_id,
                    }),
                ))
            })
        {
            compact.entry(wire).or_default().insert(key, owner);
        }
        self.origins = Arc::new(compact);
        self.foreign.clear();
        for index in 0..self.exchanges.len() {
            self.classify_origin(index);
        }
        tracing::info!(
            foreign_exchanges = self.foreign.len(),
            cache_reused,
            source_bytes,
            "prepared MySQL dependency ownership"
        );
    }

    pub(super) fn classify_origin(&mut self, index: usize) {
        if self.origins.is_empty() {
            return;
        }
        let exchange = &self.exchanges[index];
        if exchange.source != ReplaySource::Case {
            return;
        }
        let Some(case) = exchange.case_id.as_deref() else {
            return;
        };
        let record = &exchange.record;
        let Some(proofs) = record
            .connection_id
            .zip(record.query_sequence)
            .and_then(|wire| self.origins.get(&wire))
        else {
            return;
        };
        if !matches!(record.response.status.as_str(), "ok" | "resultset") {
            return;
        }
        // No rows or SQL values enter this lookup or the public ownership report.
        let summary = serde_json::json!({"command":record.command,
            "target_host":exchange.identity.target.host,"target_port":exchange.identity.target.port,
            "database":exchange.identity.database,"username":exchange.identity.username,
            "connection_id":record.connection_id,"query_sequence":record.query_sequence,
            "status":record.response.status,"sql_summary":{"fingerprint":record.sql.as_deref()
                .map(crate::config::process_owned_dependencies::mysql::evidence::fingerprint)}});
        if let Some(origin) = crate::config::api_trigger::mysql::wire_key(case, &summary)
            .and_then(|key| proofs.get(&key))
        {
            self.foreign.insert(index, origin.clone());
        }
    }
}

impl ReplayState {
    pub(crate) fn process_owned_mysql(&self) -> Vec<OwnedExchange> {
        let mut exchanges: Vec<_> = self
            .protocols
            .mysql
            .foreign
            .iter()
            .filter(|(index, _)| self.mysql_exchange_is_unused(**index, ReplaySource::Case, None))
            .map(|(index, witness)| OwnedExchange {
                exchange: self.mysql_summary(*index),
                ownership_rule: witness.rule.clone(),
                trigger_case_id: witness.trigger_case_id.clone(),
            })
            .collect();
        exchanges.sort_unstable_by_key(|row| row.exchange.index);
        exchanges
    }
}

pub(super) type Foreign = HashMap<usize, Arc<Owner>>;
