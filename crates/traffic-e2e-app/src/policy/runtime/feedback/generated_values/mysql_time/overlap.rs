//! Admission rejects time rules whose token ownership would conflict at Replay.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::runtime::sql_template::SqlValueTemplate;
use anyhow::Context;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn validate(
    proposed: &ReplayDependencyRule,
    existing: &[ReplayDependencyRule],
) -> Result<()> {
    let selected = proposed
        .mysql
        .as_ref()
        .context("joint time rule lacks SQL")?;
    let proposed_template = SqlValueTemplate::new(
        &selected.sql,
        &selected.tables,
        &selected.table_patterns,
        selected.table_series.as_ref(),
    )?;
    let positions = selected_positions(proposed_template.tokens(), &selected.sql_values);
    for rule in existing.iter().filter(|rule| rule.id != proposed.id) {
        if !crate::policy::runtime::case_condition::overlaps(
            rule.when.as_ref(),
            proposed.when.as_ref(),
        ) {
            continue;
        }
        let Some(mysql) = &rule.mysql else {
            continue;
        };
        if mysql.sql_values.is_empty() && mysql.params.is_empty()
            || rule.target.host.as_ref().is_some_and(|host| {
                proposed.target.host.as_ref().is_some_and(|target| {
                    !host
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(target.trim_end_matches('.'))
                })
            })
            || rule
                .target
                .port
                .zip(proposed.target.port)
                .is_some_and(|(left, right)| left != right)
            || mysql
                .database
                .as_ref()
                .zip(selected.database.as_ref())
                .is_some_and(|(left, right)| left != right)
        {
            continue;
        }
        if !mysql.params.is_empty() {
            // Legacy parameter selectors use glob matching. The joint witness
            // checks real Runtime selectors for an exact capture. A table
            // family must also protect other declared, unobserved shards.
            let table_family = !selected.tables.is_empty()
                || !selected.table_patterns.is_empty()
                || selected.table_series.is_some();
            let disjoint_verbs = fixed_verb(&selected.sql)
                .zip(fixed_verb(&mysql.sql))
                .is_some_and(|(left, right)| !left.eq_ignore_ascii_case(right));
            ensure!(
                !table_family || disjoint_verbs,
                "joint MySQL table family may overlap legacy parameter rule {}; revise the existing contract before planning the table family",
                rule.id
            );
            continue;
        }
        ensure!(
            !mysql.sql.is_empty(),
            "joint SQL time rule conflicts with an unbounded parameter rule {}",
            rule.id
        );
        let template = SqlValueTemplate::new(
            &mysql.sql,
            &mysql.tables,
            &mysql.table_patterns,
            mysql.table_series.as_ref(),
        )?;
        if !proposed_template.overlaps(&template) {
            continue;
        }
        ensure!(
            mysql.params.is_empty(),
            "joint SQL time rule conflicts with parameter rule {}",
            rule.id
        );
        let existing_positions = selected_positions(template.tokens(), &mysql.sql_values);
        ensure!(
            positions.is_disjoint(&existing_positions),
            "joint SQL time rule overlaps the existing SQL token ownership of {}; reuse or revise the existing contract",
            rule.id
        );
    }
    Ok(())
}

fn fixed_verb(sql: &str) -> Option<&str> {
    sql.split_ascii_whitespace().next().filter(|verb| {
        ["select", "insert", "update", "delete"]
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(verb))
    })
}

fn selected_positions(
    tokens: &[Token],
    values: &BTreeMap<usize, crate::policy::runtime::config::MysqlTimeValueRule>,
) -> BTreeSet<usize> {
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == Token::Placeholder)
        .enumerate()
        .filter_map(|(slot, (position, _))| values.contains_key(&slot).then_some(position))
        .collect()
}
