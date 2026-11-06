//! Source-scoped SQL value rules, complete witnesses and atomic accounting.
use super::*;
use crate::policy::{CompiledRule, Protocol, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
};
use crate::replay::{RecordedMysqlExchange, RecordedMysqlValue, ReplaySessionIdentity};
use crate::value_contract::json::AnchorClocks;
impl RequestContracts {
    pub(in crate::replay) fn has_mysql_formats(
        &self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> bool {
        self.has_mysql_formats_in_scope(identity, record, false)
    }

    pub(in crate::replay) fn has_authored_mysql_formats(
        &self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
    ) -> bool {
        self.has_mysql_formats_in_scope(identity, record, true)
    }

    fn has_mysql_formats_in_scope(
        &self,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        authored_only: bool,
    ) -> bool {
        let Some(policy) = self
            .compiled_rules()
            .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some())
        else {
            return false;
        };
        if authored_only
            && policy.mysql.is_none()
            && policy
                .global_json
                .as_ref()
                .is_none_or(|plan| plan.fields.is_empty())
        {
            return false;
        }
        let Ok(tokens) = super::super::matcher::mysql_values::materialized(
            record.sql.as_deref(),
            record.params.as_deref(),
        ) else {
            return false;
        };
        let context = crate::replay::mysql::contracts::automatic::RequestContext::new(
            policy,
            self.mysql_automatic
                .lock()
                .expect("MySQL inference metadata")
                .clone(),
            identity,
            record,
        );
        let clocks = self.contract_clocks(
            None,
            crate::replay::mysql::contracts::source_started(record),
            None,
            None,
            None,
        );
        // A malformed declared field must still reach normal validation.
        if authored_only {
            context.selects_authored_values(&tokens, record.database.as_deref(), clocks)
        } else {
            context.selects_values(&tokens, record.database.as_deref(), clocks)
        }
        .unwrap_or(true)
    }
    /// PREPARE can prove SQL shape; runtime execution retains all value checks.
    pub(in crate::replay) fn mysql_fields_metadata_matches(
        &self,
        _case: Option<&str>,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        sql: &str,
    ) -> bool {
        if record.database != identity.database
            || !self
                .compiled_rules()
                .is_some_and(|policy| policy.global_json.is_some() || policy.mysql.is_some())
        {
            return false;
        }
        let Ok(source) = super::super::matcher::mysql_values::materialized(
            record.sql.as_deref(),
            record.params.as_deref(),
        ) else {
            return false;
        };
        let Some(actual) = crate::mysql::sql::bounds::statement_shared(sql) else {
            return false;
        };
        source.len() == actual.len()
            && source.iter().zip(actual.iter()).all(|(source, actual)| {
                source == actual
                    || (source.is_value()
                        && (actual.is_value() || *actual == crate::mysql::sql::Token::Placeholder))
            })
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
        // Most candidates differ in statement/table shape. Reject those before
        // selecting field contracts or touching the AST analysis cache.
        let token_pair = (
            record
                .sql
                .as_deref()
                .and_then(crate::mysql::sql::bounds::statement_shared),
            sql.and_then(crate::mysql::sql::bounds::statement_shared),
        );
        let scalar = |token: &crate::mysql::sql::Token| {
            token.is_value() || *token == crate::mysql::sql::Token::Placeholder
        };
        let related = match &token_pair {
            (Some(source), Some(actual)) => {
                source.len() == actual.len()
                    && source.iter().zip(actual.iter()).all(|(source, actual)| {
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
            {
                return None;
            }
            return Some(Err(
                "Target SQL differs from the recorded physical statement".into(),
            ));
        }
        let rules = Vec::<&CompiledRule>::new();
        let native = self.mysql_native_value_rules(case, identity, record);
        let automatic = self
            .compiled_rules()
            .filter(|policy| policy.global_json.is_some() || policy.mysql.is_some());
        // A global format map is not a positional SQL contract. If it selects
        // no Source value, retain ordinary predicate/projection compatibility
        // instead of rejecting an otherwise equivalent IN-list permutation.
        if rules.is_empty()
            && native.is_empty()
            && (automatic.is_none() || !self.has_mysql_formats(identity, record))
        {
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
                let copies = case.map(|case| {
                    super::super::matcher::mysql_native::CopyProofs::runtime(
                        self,
                        case,
                        clocks.dependency,
                    )
                });
                let comparison = if let Some(policy) = automatic {
                    let context = crate::replay::mysql::contracts::automatic::RequestContext::new(
                        policy,
                        self.mysql_automatic
                            .lock()
                            .expect("MySQL inference metadata")
                            .clone(),
                        identity,
                        record,
                    );
                    super::super::matcher::mysql_native::compare_with_automatic(
                        record.database.as_deref(),
                        record.sql.as_deref(),
                        record.params.as_deref(),
                        sql,
                        params,
                        &rules,
                        &native,
                        clocks,
                        copies,
                        &context,
                    )?
                } else {
                    super::super::matcher::mysql_native::compare_with_time_copies(
                        record.database.as_deref(),
                        record.sql.as_deref(),
                        record.params.as_deref(),
                        sql,
                        params,
                        &rules,
                        &native,
                        clocks,
                        copies,
                    )?
                };
                ensure!(
                    comparison.passed(),
                    "SQL value contract failed: {:?}",
                    comparison.differences
                );
                let identity = case
                    .map(|case| self.identity_decision(case, &comparison))
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
        let Some(policy) = self.compiled_rules() else {
            return vec![];
        };
        let state = self.state.lock().expect("request contracts");
        let Some(anchor) = case.and_then(|id| state.cases.get(id)) else {
            return vec![];
        };
        let mut statement = None;
        self.native_dispatch
            .candidates(
                crate::protocol_contract::ProtocolKind::Mysql,
                identity.target.as_ref(),
                &record.command,
            )
            .filter_map(|index| {
                let compiled = &policy.native[index];
                let rule = &compiled.rule;
                let matches = matches!(&rule.effect, crate::policy::NativeEffect::MysqlValues(effect)
                    if !effect.values.is_empty() || !effect.params.is_empty())
                    && rule.selector.api.as_deref().is_none_or(|api| {
                        api.split_once(' ').is_some_and(|(method, path)| {
                            method == anchor.method
                                && super::super::pattern::path_pattern_matches(path, &anchor.path)
                        })
                    })
                    && rule.when.as_ref().is_none_or(|condition| {
                        anchor.source_body.as_ref().is_some_and(|body| condition.matches_body(body))
                    })
                    && rule.selector.resource.as_ref().is_some_and(|resource| {
                        resource.database.as_ref().is_none_or(|database| {
                            database.name() == identity.database.as_deref()
                        }) && resource.username.as_deref().is_none_or(|username| {
                            Some(username) == identity.username.as_deref()
                        })
                    })
                    && self.native_dispatch.sql_could_match(index, record.sql.as_deref())
                    && statement
                        .get_or_insert_with(|| self.mysql_hypothesis_source(record).ok())
                        .as_ref()
                        .is_some_and(|tokens| self.native_dispatch.sql_matches(index, tokens));
                matches.then_some(compiled)
            })
            .collect()
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
        if self
            .compiled_rules()
            .is_some_and(|policy| policy.mysql.is_some() || policy.global_json.is_some())
        {
            self.mysql_automatic
                .lock()
                .expect("MySQL inference metadata")
                .observe(&identity, &record);
        }
        let clocks = self.contract_clocks(
            Some(case),
            crate::replay::mysql::contracts::source_started(&record),
            None,
            record.timestamp,
            None,
        );
        let automatic = crate::replay::mysql::contracts::automatic::validate_source_record(
            self, &identity, &record, clocks,
        )?;
        ensure!(
            automatic.passed(),
            "Source automatic MySQL value contract failed: {:?}",
            automatic.differences
        );
        self.observe_value_slot_applicable(automatic.evaluated);
        for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
            let raw =
                crate::replay::mysql::contracts::source_witness_from_record(&record, surface)?;
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
        }

        Ok(())
    }
}

#[cfg(test)]
mod global_tests;
