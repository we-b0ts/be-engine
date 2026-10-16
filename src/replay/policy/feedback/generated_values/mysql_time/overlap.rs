//! Admission rejects time rules whose token ownership would conflict at Replay.
use super::*;
use crate::replay::policy::sql_template::{SqlValueTemplate, bounded_tokens, extract};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::replay::policy::feedback::generated_values) fn validate(
    proposed: &ReplayDependencyRule,
    existing: &[ReplayDependencyRule],
) -> Result<()> {
    let selected = proposed
        .mysql
        .as_ref()
        .context("joint time rule lacks SQL")?;
    let tokens = bounded_tokens(&selected.sql).context("invalid joint SQL template")?;
    let positions = selected_positions(&tokens, &selected.sql_values);
    for rule in existing.iter().filter(|rule| rule.id != proposed.id) {
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
            // checks their real Runtime selectors on both normalized requests.
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
        if tokens.len() != template.tokens().len() {
            continue;
        }
        // A fixed value in an older rule can intersect a placeholder in the
        // proposed template. Test that intersection without treating SQL words,
        // table identities or function expressions as replaceable values.
        let probe: Vec<_> = tokens
            .iter()
            .zip(template.tokens())
            .map(|(actual, expected)| {
                if *actual == Token::Placeholder && expected.is_value() {
                    expected.clone()
                } else {
                    actual.clone()
                }
            })
            .collect();
        let Some(bound) = template.bind(&probe) else {
            continue;
        };
        if extract(&bound, &probe).is_none() {
            continue;
        }
        ensure!(
            mysql.params.is_empty(),
            "joint SQL time rule conflicts with parameter rule {}",
            rule.id
        );
        let existing_positions = selected_positions(&bound, &mysql.sql_values);
        ensure!(
            positions.is_disjoint(&existing_positions),
            "joint SQL time rule overlaps the existing SQL token ownership of {}; reuse or revise the existing contract",
            rule.id
        );
    }
    Ok(())
}

fn selected_positions(
    tokens: &[Token],
    values: &BTreeMap<usize, crate::replay::policy::config::MysqlTimeValueRule>,
) -> BTreeSet<usize> {
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == Token::Placeholder)
        .enumerate()
        .filter_map(|(slot, (position, _))| values.contains_key(&slot).then_some(position))
        .collect()
}
