//! Bind one SQL predicate value to the identity captured by an API origin.
use super::*;
use crate::{
    config::MysqlBackgroundSelector,
    mysql::sql::{Token, tokens},
};

pub(crate) fn validate(rule: &BackgroundDependencyRuleConfig) -> Result<()> {
    let BackgroundDependencyRuleConfig::Mysql {
        selector,
        trigger_source,
        identity_value_index,
        include_transaction_boundaries,
        transaction_members,
        ..
    } = rule
    else {
        return Ok(());
    };
    ensure!(
        transaction_members.len() <= 16
            && (transaction_members.is_empty()
                || (*include_transaction_boundaries && trigger_source.is_some())),
        "transaction_members require an API origin and include_transaction_boundaries"
    );
    for member in transaction_members {
        member.validate()?;
        ensure!(
            member
                .target_host
                .eq_ignore_ascii_case(&selector.target_host)
                && member.target_port == selector.target_port
                && member.database == selector.database
                && member.username == selector.username,
            "transaction members must use the anchor endpoint/database/user"
        );
    }
    match (trigger_source, identity_value_index) {
        (None, None) if !include_transaction_boundaries => Ok(()),
        (Some(source), Some(index)) => {
            source.validate()?;
            ensure!(
                identity_position(selector, *index).is_some(),
                "identity_value_index must select an equality or singleton IN predicate after WHERE; OR is unsupported"
            );
            Ok(())
        }
        _ => {
            anyhow::bail!("MySQL trigger_source and identity_value_index must be provided together")
        }
    }
}

fn identity_position(selector: &MysqlBackgroundSelector, index: usize) -> Option<usize> {
    let template = selector.api_template()?;
    let pos = template
        .iter()
        .enumerate()
        .filter(|(_, t)| **t == Token::Placeholder)
        .nth(index)?
        .0;
    let where_pos = template.iter().position(|t| t.is("where"))?;
    if pos <= where_pos || template.iter().any(|t| t.is("or") || t.is("not")) {
        return None;
    }
    let end = template
        .iter()
        .position(|t| {
            ["order", "limit", "group", "having"]
                .iter()
                .any(|s| t.is(s))
        })
        .unwrap_or(template.len());
    if pos >= end {
        return None;
    }
    let column = |t: &Token| matches!(t, Token::Word(_) | Token::Identifier(_));
    let equality = pos
        .checked_sub(2)
        .is_some_and(|p| column(&template[p]) && template[p + 1].is("="))
        && template.get(pos + 1).is_none_or(|t| {
            ["and", ")", "order", "limit", "group"]
                .iter()
                .any(|s| t.is(s))
        });
    let singleton_in = pos.checked_sub(3).is_some_and(|p| {
        column(&template[p]) && template[p + 1].is("in") && template[p + 2].is("(")
    }) && template.get(pos + 1).is_some_and(|t| t.is(")"))
        && template.get(pos + 2).is_none_or(|t| {
            ["and", ")", "order", "limit", "group"]
                .iter()
                .any(|s| t.is(s))
        });
    (equality || singleton_in).then_some(pos)
}

pub(crate) fn identity(rule: &BackgroundDependencyRuleConfig, event: &Value) -> Option<String> {
    let BackgroundDependencyRuleConfig::Mysql {
        selector,
        trigger_source: Some(_),
        identity_value_index: Some(index),
        ..
    } = rule
    else {
        return None;
    };
    let sql = event["sql"].as_str()?;
    let expected = selector.sql.split_whitespace().next().unwrap_or_default();
    let actual = sql.split_whitespace().next().unwrap_or_default();
    if [
        "select", "update", "insert", "delete", "commit", "rollback", "begin", "set",
    ]
    .iter()
    .any(|s| actual.eq_ignore_ascii_case(s))
        && !expected.eq_ignore_ascii_case(actual)
    {
        return None;
    }

    if event["event_type"] != "mysql_exchange"
        || !selector.matches_api_query(
            event["target_host"].as_str(),
            event["target_port"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok()),
            event["database"].as_str(),
            event["username"].as_str(),
            event["command"].as_str()?,
            Some(sql),
        )
    {
        return None;
    }
    let ts = tokens(sql)?;
    let Token::Number(id) = ts.get(identity_position(selector, *index)?)? else {
        return None;
    };
    crate::mysql::sql::positive_integer(id)
}

pub(crate) fn complete(event: &Value) -> bool {
    event["outcome"] == "response"
        && event["parse_warnings"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && (crate::config::process_owned_dependencies::mysql::evidence::complete_response(event)
            || (event["sql"]
                .as_str()
                .is_some_and(|s| s.trim_start().to_ascii_uppercase().starts_with("UPDATE "))
                && event["response"]["status"] == "ok"
                && event["response"]["affected_rows"]
                    .as_u64()
                    .is_some_and(|n| n <= 1)))
}

/// Replay's MySQL summaries identify the SQL and endpoint, not a wire sequence.
/// Every identical immutable exchange must therefore have compatible origin proof.
pub(crate) fn key(case: &str, event: &Value) -> Option<String> {
    let sql = event["sql"]
        .as_str()
        .map(crate::config::process_owned_dependencies::mysql::evidence::fingerprint)
        .or_else(|| {
            event["sql_summary"]["fingerprint"]
                .as_str()
                .map(str::to_owned)
        })?;
    let host = event["target_host"]
        .as_str()
        .or_else(|| event["target"]["host"].as_str())?
        .to_ascii_lowercase();
    let port = event["target_port"]
        .as_u64()
        .or_else(|| event["target"]["port"].as_u64())?;
    Some(format!(
        "{case}/mysql/{}",
        serde_json::to_string(&(
            host,
            port,
            event["database"].as_str()?,
            event["username"].as_str()?,
            event["command"].as_str()?,
            sql
        ))
        .ok()?
    ))
}

pub(crate) fn disabled(value: &bool) -> bool {
    !value
}

/// New summaries preserve immutable wire identity. Never fall back to an
/// ambiguous SQL-only match when an explicit identity is present.
pub(crate) fn wire_key(case: &str, event: &Value) -> Option<String> {
    Some(format!(
        "{}/{}/{}",
        key(case, event)?,
        event["connection_id"].as_str()?,
        event["query_sequence"].as_u64()?
    ))
}

pub(crate) fn summary_key(case: &str, event: &Value) -> Option<String> {
    wire_key(case, event).or_else(|| key(case, event))
}
