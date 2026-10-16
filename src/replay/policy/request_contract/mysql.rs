//! Source-scoped SQL value rules, complete witnesses and atomic accounting.
use super::*;
use crate::policy::{CompiledRule, Protocol, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
};
use crate::replay::{RecordedMysqlExchange, RecordedMysqlValue, ReplaySessionIdentity};
use crate::value_contract::json::AnchorClocks;

impl RequestContracts {
    pub(in crate::replay) fn mysql_compiled_rules(
        &self,
        surface: Surface,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> Vec<&CompiledRule> {
        self.compiled_rules()
            .into_iter()
            .flat_map(|compiled| &compiled.rules)
            .filter(|compiled| {
                let rule = &compiled.rule;
                rule.surface == surface
                    && self.matches_compiled_case(compiled, case)
                    && rule.selector.resource.as_ref().is_some_and(|r| {
                        r.protocol == Protocol::Mysql
                            && identity.target.as_ref().is_some_and(|t| {
                                t.host.eq_ignore_ascii_case(&r.endpoint.host)
                                    && t.port == r.endpoint.port
                            })
                            && r.database
                                .as_ref()
                                .is_none_or(|d| d.name() == identity.database.as_deref())
                            && r.username
                                .as_deref()
                                .is_none_or(|u| Some(u) == identity.username.as_deref())
                    })
                    && rule.selector.operation.as_deref() == Some(record.command.as_str())
                    && rule.selector.sql.as_deref().is_some_and(|sql| {
                        super::super::sql_template::SqlValueTemplate::new(sql, &[], &[], None)
                            .ok()
                            .is_some_and(|template| {
                                super::super::matcher::mysql_values::template_values(
                                    &template,
                                    record.sql.as_deref(),
                                    record.params.as_deref(),
                                )
                                .is_ok()
                            })
                    })
            })
            .collect()
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn preview_mysql_values(
        &self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        observed: DateTime<Utc>,
    ) -> Option<Result<super::super::matcher::DependencyRuleDecision, String>> {
        let rules = self.mysql_compiled_rules(Surface::DependencyRequest, case, identity, record);
        if rules.is_empty() {
            return None;
        }
        Some(
            (|| {
                ensure!(
                    record.command == command,
                    "SQL command differs from the declared operation"
                );
                let clocks = self.contract_clocks(
                    case,
                    crate::replay::mysql::contracts::source_started(record),
                    Some(observed),
                    None,
                    None,
                );
                let comparison = super::super::matcher::mysql_contract::compare_values(
                    record.sql.as_deref(),
                    record.params.as_deref(),
                    sql,
                    params,
                    &rules,
                    clocks,
                )?;
                ensure!(
                    comparison.passed(),
                    "SQL value contract failed: {:?}",
                    comparison.differences
                );
                let mut decision = super::super::matcher::DependencyRuleDecision::default();
                decision
                    .value_contracts
                    .push(Decision::from_value_comparison(comparison));
                Ok(decision)
            })()
            .map_err(|error: anyhow::Error| error.to_string()),
        )
    }
    pub(in crate::replay) fn mysql_metadata(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        surface: Surface,
        slot: Slot,
        role: TargetRole,
        clocks: AnchorClocks,
    ) -> WitnessMetadata {
        let pair = |p: crate::value_contract::time::ClockPair| ClockPair {
            source: p.source,
            target: p.target,
        };
        WitnessMetadata {
            surface,
            source_role: if surface == Surface::DependencyRequest {
                SourceRole::RecordedDependencyRequest
            } else {
                SourceRole::RecordedDependencyResponse
            },
            target_role: role,
            source: SourceIdentity {
                case_id: case.into(),
                exchange_id: None,
                connection_id: record.connection_id.map(|id| id.to_string()),
                sequence: record.query_sequence,
            },
            resource: identity.target.as_ref().map(|t| crate::policy::Resource {
                protocol: Protocol::Mysql,
                endpoint: crate::policy::Endpoint {
                    host: t.host.clone(),
                    port: t.port,
                },
                database: identity.database.clone().map(crate::policy::Database::Name),
                username: identity.username.clone(),
            }),
            operation: record.command.clone(),
            slot,
            clocks: WitnessClocks {
                case: pair(clocks.case),
                dependency: pair(clocks.dependency),
                delivery: pair(clocks.delivery),
            },
        }
    }
    pub(super) fn observe_unified_mysql_source(&self, case: &str, event: &Value) -> Result<()> {
        if self.compiled.is_none() || event["event_type"] != "mysql_exchange" {
            return Ok(());
        }
        let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
        let Some(source_identity) = crate::replay::identity_from_exchange(&record) else {
            return Ok(());
        };
        let identity = ReplaySessionIdentity {
            target: Some(source_identity.target),
            database: source_identity.database,
            username: source_identity.username,
        };
        let clocks = self.contract_clocks(
            Some(case),
            crate::replay::mysql::contracts::source_started(&record),
            None,
            record.timestamp,
            None,
        );
        for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
            let rules = self.mysql_compiled_rules(surface, Some(case), &identity, &record);
            let raw = crate::replay::mysql::contracts::source_witness(event, surface)?;
            if rules.is_empty() {
                // No configured permission is needed to retain immutable evidence.
                let slot = if surface == Surface::DependencyRequest {
                    Slot::SqlValue(0)
                } else {
                    Slot::SqlColumn(String::new())
                };
                self.record_value_witness(
                    self.mysql_metadata(
                        case,
                        &identity,
                        &record,
                        surface,
                        slot,
                        TargetRole::Unavailable,
                        clocks,
                    ),
                    &raw,
                    None,
                )?;
                continue;
            }
            let mut slots = BTreeSet::new();
            for rule in rules {
                let available = surface == Surface::DependencyRequest
                    || (record.outcome == crate::DependencyExchangeOutcome::Response
                        && record.response.status == "resultset"
                        && !crate::replay::mysql::contracts::witness_values(&raw, surface, rule)?
                            .is_empty());
                if available {
                    self.observe_value_slot_applicable([rule.rule.id.clone()]);
                } else {
                    self.observe_value_slot_unavailable([rule.rule.id.clone()]);
                }
                if slots.insert(serde_json::to_string(&rule.rule.slot)?) {
                    self.record_value_witness(
                        self.mysql_metadata(
                            case,
                            &identity,
                            &record,
                            surface,
                            rule.rule.slot.clone(),
                            TargetRole::Unavailable,
                            clocks,
                        ),
                        &raw,
                        None,
                    )?;
                }
            }
        }
        Ok(())
    }
}
