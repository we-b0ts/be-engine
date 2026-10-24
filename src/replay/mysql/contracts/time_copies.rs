//! Retain selected Source time leaves until their real response is delivered.
use super::*;
use crate::mysql::sql::{
    bounds,
    field_bindings::{self, FieldIdentity},
};
use crate::replay::policy::request_contract::RequestContracts;
use crate::value_contract::time_copies::{self, TimeCopyLeaf, TimeCopyPosition};
use sha2::{Digest, Sha256};

type Recorder<'a> = dyn FnMut(
        TimeCopyPosition<'_>,
        TimeCopyPosition<'_>,
        &str,
        &str,
        &Value,
        &Value,
        &crate::policy::TimeContract,
    ) -> Result<()>
    + 'a;

#[derive(Debug, Clone)]
struct Column {
    index: usize,
    origin: FieldIdentity,
    rule: CompiledRule,
    rows: Vec<Row>,
}
#[derive(Debug, Clone)]
struct Row {
    index: usize,
    digest: [u8; 32],
    leaves: Vec<TimeCopyLeaf>,
}
#[derive(Debug, Clone)]
struct InputWitness {
    source: Arc<[u8]>,
    request: RequestEnvelope,
    metadata: Vec<WitnessMetadata>,
    observation_id: uuid::Uuid,
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct PreparedRead {
    owner: Option<RequestContracts>,
    case: String,
    host: String,
    port: u16,
    columns: Vec<Column>,
    row_count: usize,
    source_completed_at: Option<chrono::DateTime<Utc>>,
    witness: Option<InputWitness>,
}

fn analysis(
    response: &RecordedMysqlResponse,
    sql: Option<&str>,
    database: Option<&str>,
) -> Option<Arc<field_bindings::FieldAnalysis>> {
    response
        .columns
        .iter()
        .any(|column| {
            column.database.is_none() || column.table.is_none() || column.column.is_none()
        })
        .then(|| {
            sql.and_then(bounds::statement)
                .and_then(|tokens| field_bindings::analyze(&tokens, database))
        })
        .flatten()
}

/// Called after a proven projection and materialization, before input rewriting.
/// Keep declared active time leaves and carrier hashes, never another JSON tree.
pub(in crate::replay) fn prepare(
    owner: &RequestContracts,
    case: &str,
    identity: &ReplaySessionIdentity,
    original: &RecordedMysqlExchange,
    projected: &RecordedMysqlResponse,
    projected_sql: Option<&str>,
) -> Result<Option<PreparedRead>> {
    let rules =
        owner.mysql_compiled_rules(Surface::DependencyResponse, Some(case), identity, original);
    let mut pending = from_rules(
        case,
        identity,
        original.database.as_deref(),
        projected,
        projected_sql,
        &rules,
        original.timestamp,
    )?;
    if let Some(pending) = &mut pending {
        pending.owner = Some(owner.clone());
    }
    Ok(pending)
}

fn from_rules(
    case: &str,
    identity: &ReplaySessionIdentity,
    database: Option<&str>,
    projected: &RecordedMysqlResponse,
    projected_sql: Option<&str>,
    rules: &[&CompiledRule],
    source_completed_at: Option<chrono::DateTime<Utc>>,
) -> Result<Option<PreparedRead>> {
    if source_completed_at.is_none() || projected.status != "resultset" || projected.rows_truncated
    {
        return Ok(None);
    }
    let rules = rules
        .iter()
        .copied()
        .filter(|rule| {
            rule.rule.surface == Surface::DependencyResponse
                && matches!(rule.rule.slot, Slot::SqlField(_))
                && time_copies::schema_rule(&rule.rule.id)
                && rule
                    .rule
                    .contract
                    .values()
                    .any(|field| field.unconditional().time().is_some())
                && rule
                    .rule
                    .selector
                    .resource
                    .as_ref()
                    .is_some_and(|resource| {
                        identity.target.as_ref().is_some_and(|target| {
                            target.host.eq_ignore_ascii_case(&resource.endpoint.host)
                                && target.port == resource.endpoint.port
                        }) && resource
                            .username
                            .as_deref()
                            .is_none_or(|username| Some(username) == identity.username.as_deref())
                    })
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return Ok(None);
    }
    let source_analysis = analysis(projected, projected_sql, database);
    let mut columns = Vec::new();
    let mut leaf_count = 0_usize;
    for rule in rules {
        for index in fields::response_indices_in(projected, rule, source_analysis.as_deref())? {
            let Some(origin) =
                fields::response_origin(projected, index, source_analysis.as_deref())
            else {
                continue;
            };
            let mut rows = Vec::new();
            for (row, values) in projected.rows.iter().enumerate() {
                let value = values
                    .get(index)
                    .context("SQL time-copy read row is incomplete")?;
                let Some(bytes) = fields::value_bytes(value, &rule.rule.codec)? else {
                    continue;
                };
                let decoded = rule.codec_plan.decode(&bytes)?;
                let leaves = time_copies::leaves(&decoded.logical, rule)?;
                leaf_count = leaf_count.saturating_add(leaves.len());
                ensure!(
                    leaf_count <= 4096,
                    "SQL read time provenance exceeds 4096 selected leaves"
                );
                if !leaves.is_empty() {
                    rows.push(Row {
                        index: row,
                        digest: Sha256::digest(&bytes).into(),
                        leaves,
                    });
                }
            }
            if !rows.is_empty() {
                columns.push(Column {
                    index,
                    origin,
                    rule: rule.clone(),
                    rows,
                });
            }
        }
    }
    if columns.is_empty() {
        return Ok(None);
    }
    let endpoint = identity
        .target
        .as_ref()
        .context("SQL time-copy read lacks actual endpoint")?;
    Ok(Some(PreparedRead {
        owner: None,
        case: case.into(),
        host: endpoint.host.clone(),
        port: endpoint.port,
        columns,
        row_count: projected.rows.len(),
        source_completed_at,
        witness: None,
    }))
}

impl PreparedRead {
    /// Protected evidence is retained only in managed witness mode. Share an
    /// existing delivery's immutable Source envelope when one was prepared.
    pub(in crate::replay) fn prepare_witness(
        &mut self,
        original: &RecordedMysqlExchange,
        identity: &ReplaySessionIdentity,
        request: ObservedRequest<'_>,
        delivery: Option<&PreparedDelivery>,
    ) -> Result<()> {
        let Some(owner) = self
            .owner
            .as_ref()
            .filter(|owner| owner.retains_value_witnesses())
        else {
            return Ok(());
        };
        let source = if let Some(delivery) = delivery {
            delivery.original.clone()
        } else {
            let response = original.response.materialize()?;
            response_witness(
                RequestEnvelope::recorded(original),
                original.timestamp,
                original.outcome,
                &response,
            )?
            .into()
        };
        let clocks = owner.contract_clocks(
            Some(&self.case),
            source_started(original),
            Some(request.started_at),
            original.timestamp,
            None,
        );
        let mut slots = BTreeSet::new();
        let mut metadata = Vec::new();
        for column in &self.columns {
            if slots.insert(serde_json::to_string(&column.rule.rule.slot)?) {
                metadata.push(owner.mysql_metadata(
                    &self.case,
                    identity,
                    original,
                    (Surface::DependencyResponse, column.rule.rule.slot.clone()),
                    TargetRole::DeliveredInput,
                    clocks,
                ));
            }
        }
        self.witness = Some(InputWitness {
            source,
            request: RequestEnvelope::observed(request),
            metadata,
            observation_id: request.observation_id.unwrap_or_else(uuid::Uuid::new_v4),
        });
        Ok(())
    }

    /// Commit this observed input fact synchronously before the caller awaits
    /// the global replay ledger; another connection may immediately use it.
    pub(in crate::replay) fn commit_after_wire(
        &self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        delivered: &RecordedMysqlResponse,
        delivered_sql: Option<&str>,
    ) -> Result<()> {
        if let Some(owner) = &self.owner {
            let completed_at = Utc::now();
            self.commit(
                owner,
                case,
                identity,
                delivered,
                delivered_sql,
                completed_at,
            )?;
            if case == Some(self.case.as_str())
                && let Some(witness) = &self.witness
            {
                let target = response_witness(
                    witness.request.clone(),
                    Some(completed_at),
                    crate::DependencyExchangeOutcome::Response,
                    delivered,
                )?;
                for metadata in &witness.metadata {
                    let mut metadata = metadata.clone();
                    metadata.clocks.delivery.target = Some(completed_at);
                    owner.record_delivery_witness(
                        &witness.observation_id.to_string(),
                        metadata,
                        &witness.source,
                        &target,
                    )?;
                }
            }
        }
        Ok(())
    }
    /// Publish all actual input facts atomically after successful wire flush.
    pub(in crate::replay) fn commit(
        &self,
        owner: &RequestContracts,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        delivered: &RecordedMysqlResponse,
        delivered_sql: Option<&str>,
        delivered_at: chrono::DateTime<Utc>,
    ) -> Result<()> {
        if case != Some(self.case.as_str()) {
            return Ok(());
        }
        let mut records = Vec::new();
        self.observe_delivered(
            identity,
            delivered,
            delivered_sql,
            &mut |source,
                  target,
                  source_pattern,
                  target_pattern,
                  source_value,
                  target_value,
                  time| {
                records.push(time_copies::TimeCopyRecord::new_time(
                    time,
                    source,
                    target,
                    source_pattern,
                    target_pattern,
                    source_value,
                    target_value,
                )?);
                Ok(())
            },
        )?;
        owner.record_time_copies(
            &self.case,
            records,
            crate::value_contract::time::ClockPair {
                source: self.source_completed_at,
                target: Some(delivered_at),
            },
        )
    }

    fn observe_delivered(
        &self,
        identity: &ReplaySessionIdentity,
        delivered: &RecordedMysqlResponse,
        delivered_sql: Option<&str>,
        record: &mut Recorder<'_>,
    ) -> Result<usize> {
        if delivered.status != "resultset" || delivered.rows_truncated {
            return Ok(0);
        }
        ensure!(
            delivered.rows.len() == self.row_count,
            "SQL time-copy delivery changed row inventory"
        );
        let endpoint = identity
            .target
            .as_ref()
            .context("SQL time-copy delivery lacks actual endpoint")?;
        let target_analysis = analysis(delivered, delivered_sql, identity.database.as_deref());
        let mut recorded = 0;
        for column in &self.columns {
            let Some(target_origin) =
                fields::response_origin(delivered, column.index, target_analysis.as_deref())
            else {
                continue;
            };
            if target_origin != column.origin {
                continue;
            }
            let (Some(source_database), Some(target_database)) = (
                column.origin.database.as_deref(),
                target_origin.database.as_deref(),
            ) else {
                continue;
            };
            let mut leaf_pair = |source: &TimeCopyLeaf, target: &TimeCopyLeaf| -> Result<()> {
                record(
                    TimeCopyPosition::Mysql {
                        host: &self.host,
                        port: self.port,
                        database: source_database,
                        table: &column.origin.table,
                        column: &column.origin.column,
                    },
                    TimeCopyPosition::Mysql {
                        host: &endpoint.host,
                        port: endpoint.port,
                        database: target_database,
                        table: &target_origin.table,
                        column: &target_origin.column,
                    },
                    &source.pattern,
                    &target.pattern,
                    &source.value,
                    &target.value,
                    &source.time,
                )?;
                recorded += 1;
                Ok(())
            };
            for row in &column.rows {
                let value = delivered
                    .rows
                    .get(row.index)
                    .and_then(|row| row.get(column.index))
                    .context("SQL time-copy delivered row is incomplete")?;
                let Some(bytes) = fields::value_bytes(value, &column.rule.rule.codec)? else {
                    continue;
                };
                if <[u8; 32]>::from(Sha256::digest(&bytes)) == row.digest {
                    // Ordinary historical reads reuse their original parsed leaves.
                    for leaf in &row.leaves {
                        leaf_pair(leaf, leaf)?;
                    }
                    continue;
                }
                let decoded = column.rule.codec_plan.decode(&bytes)?;
                let target_leaves = time_copies::leaves(&decoded.logical, &column.rule)?;
                let targets = target_leaves
                    .iter()
                    .map(|leaf| ((leaf.pattern.as_str(), leaf.pointer.as_str()), leaf))
                    .collect::<BTreeMap<_, _>>();
                for source in &row.leaves {
                    if let Some(target) =
                        targets.get(&(source.pattern.as_str(), source.pointer.as_str()))
                    {
                        leaf_pair(source, target)?;
                    }
                }
            }
        }
        Ok(recorded)
    }
}

/// Offline callers authenticate both envelopes and actual resource/default DB,
/// then retain the exact same native projected Source -> delivered leaf pairs.
pub(crate) fn delivered_witness_time_copies(
    source: &[u8],
    target: &[u8],
    rules: &[&CompiledRule],
    resource: &crate::policy::Resource,
    database: Option<&str>,
    record: &mut Recorder<'_>,
) -> Result<usize> {
    let source: ResponseEnvelope = serde_json::from_slice(source)?;
    let target: ResponseEnvelope = serde_json::from_slice(target)?;
    if source.outcome != crate::DependencyExchangeOutcome::Response
        || target.outcome != source.outcome
    {
        return Ok(0);
    }
    let original: RecordedMysqlExchange = serde_json::from_value(serde_json::json!({
        "command":source.request.command,"sql":source.request.sql,"params":source.request.params,
        "database":database,"response":source.response,"outcome":source.outcome,
    }))?;
    let projected = projected_response(
        &original,
        &target.request.command,
        target.request.sql.as_deref(),
        target.request.params.as_deref(),
    )?;
    let identity = ReplaySessionIdentity {
        target: Some(TargetKey {
            host: resource.endpoint.host.clone(),
            port: resource.endpoint.port,
        }),
        database: database.map(str::to_owned),
        username: resource.username.clone(),
    };
    let Some(pending) = from_rules(
        "",
        &identity,
        database,
        &projected,
        target.request.sql.as_deref(),
        rules,
        source.response_delivered_at,
    )?
    else {
        return Ok(0);
    };
    pending.observe_delivered(
        &identity,
        &target.response,
        target.request.sql.as_deref(),
        record,
    )
}

#[cfg(test)]
mod tests;
