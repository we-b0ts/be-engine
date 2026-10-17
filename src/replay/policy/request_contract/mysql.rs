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
        let mut statement = None;
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
                    && self
                        .mysql_selection
                        .matches(&rule.id, record, &mut statement)
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
        runtime: &super::super::matcher::ReplayPolicyRuntime,
    ) -> Option<Result<super::super::matcher::DependencyRuleDecision, String>> {
        let rules = self.mysql_compiled_rules(Surface::DependencyRequest, case, identity, record);
        let native = self.mysql_native_value_rules(case, identity, record);
        if rules.is_empty() && native.is_empty() {
            return None;
        }
        Some(
            (|| {
                ensure!(
                    record.command == command
                        || matches!(
                            (record.command.as_str(), command),
                            (
                                "COM_QUERY" | "COM_STMT_EXECUTE",
                                "COM_QUERY" | "COM_STMT_EXECUTE"
                            )
                        ),
                    "SQL command differs outside the native text/prepared query adapter"
                );
                let clocks = self.contract_clocks(
                    case,
                    crate::replay::mysql::contracts::source_started(record),
                    Some(observed),
                    None,
                    None,
                );
                let comparison = super::super::matcher::mysql_native::compare(
                    record.sql.as_deref(),
                    record.params.as_deref(),
                    sql,
                    params,
                    &rules,
                    &native,
                    clocks,
                )?;
                ensure!(
                    comparison.passed(),
                    "SQL value contract failed: {:?}",
                    comparison.differences
                );
                let mut decision = super::super::matcher::mysql_native::validate_parameters(
                    runtime,
                    case.context("SQL generated parameters require a case")?,
                    record.sql.as_deref(),
                    record.params.as_deref(),
                    sql,
                    params,
                    &native,
                )?;
                decision.merge_value_comparison(comparison, &native);
                Ok(decision)
            })()
            .map_err(|error: anyhow::Error| error.to_string()),
        )
    }
    pub(in crate::replay) fn mysql_native_value_rules(
        &self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> Vec<&crate::policy::CompiledNativeRule> {
        let Some(anchor) = case.and_then(|id| self.anchor(id).ok()) else {
            return vec![];
        };
        let mut statement = None;
        self.compiled_rules().into_iter().flat_map(|compiled| &compiled.native).filter(|compiled| {
            let rule = &compiled.rule;
            matches!(&rule.effect, crate::policy::NativeEffect::MysqlValues(effect) if !effect.values.is_empty() || !effect.params.is_empty())
                && rule.selector.api.as_deref().is_none_or(|api| api.split_once(' ').is_some_and(|(method,path)|
                    method == anchor.method && super::super::pattern::path_pattern_matches(path,&anchor.path)))
                && rule.when.as_ref().is_none_or(|condition| anchor.source_body.as_ref().is_some_and(|body|condition.matches_body(body)))
                && rule.selector.resource.as_ref().is_some_and(|r| r.protocol == Protocol::Mysql
                    && identity.target.as_ref().is_some_and(|t| t.host.eq_ignore_ascii_case(&r.endpoint.host) && t.port==r.endpoint.port)
                    && r.database.as_ref().is_none_or(|d| d.name()==identity.database.as_deref())
                    && r.username.as_deref().is_none_or(|u|Some(u)==identity.username.as_deref()))
                && rule.selector.operation.as_deref().is_none_or(|op|op==record.command)
                && self.mysql_selection.matches(&rule.id, record, &mut statement)
        }).collect()
    }
    pub(in crate::replay) fn mysql_metadata(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        location: (Surface, Slot),
        role: TargetRole,
        clocks: AnchorClocks,
    ) -> WitnessMetadata {
        let (surface, slot) = location;
        let pair = |p: crate::value_contract::time::ClockPair| ClockPair {
            source: p.source,
            target: p.target,
        };
        WitnessMetadata {
            surface,
            source_role: if surface == Surface::DependencyRequest {
                SourceRole::DependencyRequest
            } else {
                SourceRole::DependencyResponse
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
            let raw =
                crate::replay::mysql::contracts::source_witness_from_record(&record, surface)?;
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
                        (surface, slot),
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
                let values = crate::replay::mysql::contracts::witness_values(&raw, surface, rule)?;
                let available = (surface == Surface::DependencyRequest
                    || (record.outcome == crate::DependencyExchangeOutcome::Response
                        && record.response.status == "resultset"))
                    && !values.is_empty();
                if available {
                    for (_, value) in values {
                        let checked = crate::replay::contract_value::Delivery::prepare(
                            &value,
                            &[rule],
                            clocks,
                        )?;
                        self.observe_value_slot_applicable(checked.validation().evaluated.clone());
                    }
                } else {
                    self.observe_value_slot_unavailable([rule.rule.id.clone()]);
                }
                if slots.insert(serde_json::to_string(&rule.rule.slot)?) {
                    self.record_value_witness(
                        self.mysql_metadata(
                            case,
                            &identity,
                            &record,
                            (surface, rule.rule.slot.clone()),
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
