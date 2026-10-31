//! Native SQL value projection into the shared hypothesis and identity kernel.
use super::*;
use crate::mysql::sql::{Token, field_bindings};
use crate::replay::mysql::contracts;
use crate::replay::{RecordedMysqlExchange, RecordedMysqlValue, ReplaySessionIdentity};
use crate::value_contract::json::Comparison;

#[derive(Debug, Default)]
pub(super) struct ProjectionCache {
    entries: BTreeMap<String, (Arc<Vec<Token>>, usize)>,
    order: std::collections::VecDeque<String>,
    bytes: usize,
}

impl RequestContracts {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay) fn preview_mysql_hypothesis(
        &self,
        case: &str,
        identity: &ReplaySessionIdentity,
        record: &RecordedMysqlExchange,
        command: &str,
        sql: Option<&str>,
        params: Option<&[RecordedMysqlValue]>,
        observed: DateTime<Utc>,
        observation_id: Option<uuid::Uuid>,
        projected_target: Option<&[Token]>,
    ) -> Option<Result<super::super::matcher::DependencyRuleDecision>> {
        if !self.pre_match_enabled
            || !matches!(command, "COM_QUERY" | "COM_STMT_EXECUTE")
            || !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
        {
            return None;
        }
        let native = self.mysql_native_value_rules(Some(case), identity, record);
        // An explicit positional owner cannot be replaced by a hypothesis.
        if !native.is_empty() {
            return None;
        }
        Some((|| {
            if record.command == command
                && let (Some(source), Some(target)) = (record.params.as_deref(), params)
            {
                ensure!(
                    source.len() == target.len()
                        && source.iter().zip(target).all(|(a, b)| a.kind == b.kind),
                    "SQL parameter inventory or native kind differs"
                );
            }
            let source = self.mysql_hypothesis_source(record)?;
            let target_storage;
            let target = if let Some(target) = projected_target {
                target
            } else {
                target_storage = super::super::matcher::mysql_values::materialized(sql, params)
                    .map_err(anyhow::Error::msg)?;
                target_storage.as_slice()
            };
            ensure!(
                source.len() == target.len() && source.len() <= 16384,
                "SQL hypothesis preserves complete structure"
            );
            let origins = field_bindings::analyze(&source, record.database.as_deref());
            let empty = crate::policy::CompiledJsonPolicy {
                fields: Default::default(),
                fingerprint: String::new(),
                signatures: Default::default(),
            };
            let clocks = self.contract_clocks(
                Some(case),
                contracts::source_started(record),
                Some(observed),
                None,
                None,
            );
            let automatic = self.compiled_rules().map(|policy| {
                contracts::automatic::RequestContext::new(
                    policy,
                    self.mysql_automatic
                        .lock()
                        .expect("MySQL inference metadata")
                        .clone(),
                    identity,
                    record,
                )
            });
            let mut comparison = Comparison::default();
            for (position, (a, b)) in source.iter().zip(target).enumerate() {
                if a == b {
                    continue;
                }
                ensure!(
                    a.is_value() && b.is_value(),
                    "SQL non-value structure differs"
                );
                let origin = origins
                    .as_ref()
                    .and_then(|analysis| analysis.at_token(position));
                let selected = automatic
                    .as_ref()
                    .map(|context| context.select(a, b, origin, position, clocks))
                    .transpose()?
                    .flatten();
                if let Some(selected) = selected.as_ref()
                    && selected.id != crate::policy::GLOBAL_JSON_ID
                {
                    let checked = contracts::automatic::compare_selection_with_context(
                        selected,
                        clocks,
                        &[],
                        self.compiled_rules().expect("automatic policy"),
                    )?;
                    ensure!(
                        checked.passed(),
                        "authored or native temporal SQL contract failed"
                    );
                    comparison.merge_and_validate(checked);
                    continue;
                }
                let (a, b) = (sql_value(a)?, sql_value(b)?);
                ensure!(
                    origin.is_some(),
                    "SQL hypothesis requires a proven physical value slot; LIMIT and projection constants stay strict"
                );
                let plan = if a.is_object() || a.is_array() {
                    self.global_json().unwrap_or(&empty)
                } else {
                    &empty
                };
                let mut preview =
                    crate::value_contract::hypothesis::preview_values(case, &a, &b, plan, clocks);
                for considered in &mut preview.attempts {
                    sql_location(&mut considered.candidate, position, origin);
                }
                if let Some(checked) = &mut preview.comparison {
                    for candidate in &mut checked.pre_matches {
                        sql_location(candidate, position, origin);
                    }
                }
                let owner = self.with_hypothesis_context(HypothesisContext {
                    carrier: "mysql".into(), source_reference: serde_json::json!({"connection_id":record.connection_id,"sequence":record.query_sequence,"sql_token":position,"field":origin.map(|f|serde_json::json!({"database":f.database,"table":f.table,"column":f.column}))}),
                    target_observation_id: observation_id.map(|id|id.to_string()),
                });
                let checked = owner.retain_hypothesis_preview(preview).with_context(|| {
                    format!("SQL value at token {position} has no supported hypothesis")
                })?;
                comparison.merge_and_validate(checked);
            }
            ensure!(
                !comparison.pre_matches.is_empty() && comparison.passed(),
                "SQL hypothesis must explain every changed value"
            );
            let identity = self.identity_decision(case, &comparison)?;
            let mut decision = Decision::from_value_comparison(comparison);
            decision.identity = Some(identity);
            let mut result = super::super::matcher::DependencyRuleDecision::default();
            result.value_contracts.push(decision);
            Ok(result)
        })())
    }
    fn mysql_hypothesis_source(&self, record: &RecordedMysqlExchange) -> Result<Arc<Vec<Token>>> {
        let key = record
            .response
            .evidence
            .as_ref()
            .map(|reference| reference.location.sha256.as_str());
        if let Some(key) = key {
            let mut cache = self
                .mysql_hypothesis_projections
                .lock()
                .expect("SQL hypothesis projections");
            if let Some((tokens, _)) = cache.entries.get(key) {
                let tokens = tokens.clone();
                if let Some(position) = cache.order.iter().position(|candidate| candidate == key) {
                    cache.order.remove(position);
                }
                cache.order.push_back(key.into());
                return Ok(tokens);
            }
        }
        let tokens = Arc::new(
            super::super::matcher::mysql_values::materialized(
                record.sql.as_deref(),
                record.params.as_deref(),
            )
            .map_err(anyhow::Error::msg)?,
        );
        let charge = tokens.len() * std::mem::size_of::<Token>()
            + tokens
                .iter()
                .map(|token| match token {
                    Token::Bytes(value) => value.len(),
                    Token::Number(value)
                    | Token::Word(value)
                    | Token::Identifier(value)
                    | Token::Symbol(value) => value.len(),
                    _ => 0,
                })
                .sum::<usize>();
        if let Some(key) = key.filter(|_| charge <= 1024 * 1024) {
            let mut cache = self
                .mysql_hypothesis_projections
                .lock()
                .expect("SQL hypothesis projections");
            if cache.entries.contains_key(key) {
                return Ok(tokens);
            }
            while cache.entries.len() >= 256 || cache.bytes + charge > 8 * 1024 * 1024 {
                let Some(oldest) = cache.order.pop_front() else {
                    break;
                };
                if let Some((_, bytes)) = cache.entries.remove(&oldest) {
                    cache.bytes -= bytes;
                }
            }
            cache.bytes += charge;
            cache.order.push_back(key.into());
            cache.entries.insert(key.into(), (tokens.clone(), charge));
        }
        Ok(tokens)
    }
}

fn sql_value(token: &Token) -> Result<Value> {
    match token {
        Token::Bytes(bytes) => Ok(crate::json_value::parse(bytes)
            .filter(|value| value.is_object() || value.is_array())
            .unwrap_or(Value::String(std::str::from_utf8(bytes)?.into()))),
        Token::Number(number) => {
            if let Some(integer) = crate::mysql::sql::positive_integer(number)
                .and_then(|integer| integer.parse::<u64>().ok())
            {
                return Ok(Value::from(integer));
            }
            crate::json_value::parse(number.as_bytes()).context("SQL scalar preserves exact number")
        }
        Token::Null => Ok(Value::Null),
        _ => anyhow::bail!("SQL hypothesis requires a complete native value"),
    }
}

fn sql_location(
    candidate: &mut crate::value_contract::hypothesis::Candidate,
    position: usize,
    origin: Option<&field_bindings::FieldIdentity>,
) {
    let original = candidate.pointer.clone();
    candidate.pointer = format!("/sql_tokens/{position}{original}");
    candidate.command = format!("mysql.value:{position}{original}");
    candidate.draft_policy = serde_json::json!({"capability":"mysql_value","field":origin.map(|f|serde_json::json!({"database":f.database,"table":f.table,"column":f.column})),"token_index":position,"json_pointer":original,"value_policy":candidate.draft_policy});
    candidate.candidate_id = format!(
        "pre-match-{}",
        &crate::policy_evidence::digest(
            &serde_json::to_vec(&candidate.draft_policy).expect("SQL hypothesis draft")
        )[..16]
    );
}
