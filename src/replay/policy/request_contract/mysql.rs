//! Source-scoped SQL value rules, complete witnesses and atomic accounting.
use super::*;
use crate::policy::{CompiledRule, Protocol, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
};
use crate::replay::{RecordedMysqlExchange, RecordedMysqlValue, ReplaySessionIdentity};
use crate::value_contract::json::AnchorClocks;
mod raw_identities;

#[derive(Clone, Copy)]
pub(in crate::replay) struct RawMysqlIdentityRequest<'a> {
    pub source: &'a RecordedMysqlExchange,
    pub target_sql: Option<&'a str>,
    pub target_params: Option<&'a [RecordedMysqlValue]>,
}

impl RequestContracts {
    /// PREPARE proves SQL shape and physical value positions without inventing
    /// clocks or validating parameters that have not been sent yet.
    pub(in crate::replay) fn mysql_fields_metadata_matches(
        &self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        sql: &str,
    ) -> bool {
        if record.database != identity.database {
            return false;
        }
        let rules = self
            .mysql_compiled_rules(Surface::DependencyRequest, case, identity, record)
            .into_iter()
            .filter(|rule| matches!(rule.rule.slot, Slot::SqlField(_)))
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return false;
        }
        let Ok(source) = super::super::matcher::mysql_values::materialized(
            record.sql.as_deref(),
            record.params.as_deref(),
        ) else {
            return false;
        };
        let Some(actual) = crate::mysql::sql::bounds::statement(sql) else {
            return false;
        };
        if source.len() != actual.len() {
            return false;
        }
        let Some(source_fields) =
            crate::mysql::sql::field_bindings::analyze(&source, record.database.as_deref())
        else {
            return false;
        };
        let Some(actual_fields) =
            crate::mysql::sql::field_bindings::analyze(&actual, identity.database.as_deref())
        else {
            return false;
        };
        let mut selected = BTreeSet::new();
        for rule in rules {
            let Ok(positions) =
                super::super::matcher::mysql_native::fields::positions_in(rule, &source_fields)
            else {
                return false;
            };
            if super::super::matcher::mysql_native::fields::positions_in(rule, &actual_fields)
                .ok()
                .as_ref()
                != Some(&positions)
            {
                return false;
            }
            selected.extend(positions);
        }
        source
            .iter()
            .zip(&actual)
            .enumerate()
            .all(|(position, (source, actual))| {
                source == actual
                    || selected.contains(&position)
                    || (*actual == crate::mysql::sql::Token::Placeholder && source.is_value())
            })
    }

    pub(in crate::replay) fn mysql_compiled_rules(
        &self,
        surface: Surface,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> Vec<&CompiledRule> {
        self.mysql_selected_rules(surface, case, identity, record, true)
    }

    fn mysql_selected_rules(
        &self,
        surface: Surface,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        physical_fields: bool,
    ) -> Vec<&CompiledRule> {
        let mut statement = None;
        let mut field_analysis = None;
        self.compiled_rules()
            .into_iter()
            .flat_map(|compiled| {
                identity
                    .target
                    .as_ref()
                    .into_iter()
                    .flat_map(move |target| {
                        compiled.resource_rules(surface, Protocol::Mysql, &target.host, target.port)
                    })
            })
            .filter(|compiled| {
                let rule = &compiled.rule;
                (physical_fields || !matches!(rule.slot, Slot::SqlField(_)))
                    && (!matches!(rule.slot, Slot::SqlField(_))
                        || record.database == identity.database)
                    && rule.surface == surface
                    && (self.matches_compiled_case(compiled, case)
                        || (case.is_none()
                            && matches!(rule.slot, Slot::SqlField(_))
                            && rule.selector.api.is_none()
                            && rule.when.is_none()))
                    && rule.selector.resource.as_ref().is_some_and(|r| {
                        r.protocol == Protocol::Mysql
                            && identity.target.as_ref().is_some_and(|t| {
                                t.host.eq_ignore_ascii_case(&r.endpoint.host)
                                    && t.port == r.endpoint.port
                            })
                            && (matches!(rule.slot, Slot::SqlField(_))
                                || r.database
                                    .as_ref()
                                    .is_none_or(|d| d.name() == identity.database.as_deref()))
                            && r.username
                                .as_deref()
                                .is_none_or(|u| Some(u) == identity.username.as_deref())
                    })
                    && rule
                        .selector
                        .operation
                        .as_deref()
                        .is_none_or(|op| op == record.command)
                    && if matches!(rule.slot, Slot::SqlField(_)) {
                        if surface == Surface::DependencyRequest {
                            field_analysis
                                .get_or_insert_with(|| {
                                    let tokens = super::super::matcher::mysql_values::materialized(
                                        record.sql.as_deref(),
                                        record.params.as_deref(),
                                    )
                                    .ok()?;
                                    crate::mysql::sql::field_bindings::analyze(
                                        &tokens,
                                        record.database.as_deref(),
                                    )
                                })
                                .as_ref()
                                .and_then(|analysis| {
                                    super::super::matcher::mysql_native::fields::positions_in(
                                        compiled, analysis,
                                    )
                                    .ok()
                                })
                                .is_some_and(|positions| !positions.is_empty())
                        } else {
                            let analysis = field_analysis.get_or_insert_with(|| {
                                if !record.response.columns.iter().any(|c| {
                                    c.database.is_none() || c.table.is_none() || c.column.is_none()
                                }) {
                                    return None;
                                }
                                let tokens =
                                    crate::mysql::sql::bounds::statement(record.sql.as_deref()?)?;
                                crate::mysql::sql::field_bindings::analyze(
                                    &tokens,
                                    record.database.as_deref(),
                                )
                            });
                            crate::replay::mysql::contracts::fields::response_indices_in(
                                &record.response,
                                compiled,
                                analysis.as_deref(),
                            )
                            .is_ok_and(|positions| !positions.is_empty())
                        }
                    } else {
                        self.mysql_selection
                            .matches(&rule.id, record, &mut statement)
                    }
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
        self.preview_mysql_values_with_raw(
            case, identity, record, command, sql, params, observed, runtime, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn preview_mysql_values_with_raw(
        &self,
        case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        observed: DateTime<Utc>,
        runtime: &super::super::matcher::ReplayPolicyRuntime,
        raw: Option<RawMysqlIdentityRequest<'_>>,
    ) -> Option<Result<super::super::matcher::DependencyRuleDecision, String>> {
        // Most candidates differ in statement/table shape. Reject those before
        // selecting field contracts or touching the AST analysis cache.
        let token_pair = (
            record
                .sql
                .as_deref()
                .and_then(crate::mysql::sql::bounds::statement),
            sql.and_then(crate::mysql::sql::bounds::statement),
        );
        let scalar = |token: &crate::mysql::sql::Token| {
            token.is_value() || *token == crate::mysql::sql::Token::Placeholder
        };
        let related = match &token_pair {
            (Some(source), Some(actual)) => {
                source.len() == actual.len()
                    && source.iter().zip(actual).all(|(source, actual)| {
                        source == actual || scalar(source) && scalar(actual)
                    })
            }
            _ => false,
        };
        if !related {
            // Explicit SQL contracts select the immutable Source statement.
            // Retain their failed preview rather than disguising a wrong-table
            // Target request as an inapplicable rule. Generic field candidates
            // still skip AST work on unrelated statement shapes.
            if self
                .mysql_native_value_rules(case, identity, record)
                .is_empty()
                && self
                    .mysql_selected_rules(Surface::DependencyRequest, case, identity, record, false)
                    .is_empty()
            {
                return None;
            }
            return Some(Err(
                "Target SQL differs from the recorded physical statement".into(),
            ));
        }
        let rules = self.mysql_compiled_rules(Surface::DependencyRequest, case, identity, record);
        let native = self.mysql_native_value_rules(case, identity, record);
        if rules.is_empty() && native.is_empty() {
            return None;
        }
        Some(
            (|| {
                ensure!(
                    !rules
                        .iter()
                        .any(|rule| matches!(rule.rule.slot, Slot::SqlField(_)))
                        || record.database == identity.database,
                    "MySQL default database differs from its immutable Source exchange"
                );
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
                let comparison = super::super::matcher::mysql_native::compare_with_time_copies(
                    record.database.as_deref(),
                    record.sql.as_deref(),
                    record.params.as_deref(),
                    sql,
                    params,
                    &rules,
                    &native,
                    clocks,
                    case.map(|case| {
                        super::super::matcher::mysql_native::CopyProofs::runtime(
                            self,
                            case,
                            clocks.dependency,
                        )
                    }),
                )?;
                ensure!(
                    comparison.passed(),
                    "SQL value contract failed: {:?}",
                    comparison.differences
                );
                let identity = case
                    .map(|case| {
                        if let Some(raw) = raw
                            && crate::value_contract::identities::rules_have_identity(&rules)
                        {
                            let pairs = raw_identities::restore(
                                &rules,
                                record,
                                sql,
                                params,
                                raw,
                                &comparison,
                            )?;
                            self.preview_identity_pairs(case, &pairs)
                        } else {
                            self.identity_decision(case, &comparison)
                        }
                    })
                    .transpose()?;
                let mut decision = if native.is_empty() {
                    super::super::matcher::DependencyRuleDecision::default()
                } else {
                    super::super::matcher::mysql_native::validate_parameters(
                        runtime,
                        case.context("SQL generated parameters require a case")?,
                        record.sql.as_deref(),
                        record.params.as_deref(),
                        sql,
                        params,
                        &native,
                    )?
                };
                decision.merge_value_comparison(comparison, &native);
                if let Some(identity) = identity {
                    decision.value_contracts.push(super::Decision {
                        identity: Some(identity),
                        ..Default::default()
                    });
                }
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
                let values = crate::replay::mysql::contracts::witness_values(
                    &raw,
                    surface,
                    rule,
                    record.database.as_deref(),
                )?;
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

#[cfg(test)]
mod field_tests;
