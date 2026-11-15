//! Configuration validation for explicit MySQL SQL time slots.
#[cfg(test)]
use super::*;
#[cfg(test)]
use crate::mysql::sql::Token;
#[cfg(test)]
use crate::policy::runtime::sql_template::SqlValueTemplate;

#[cfg(test)]
fn validate_time_field(field: &MysqlTimeFieldRule) -> Result<()> {
    if !field.source_evidence.is_empty() {
        crate::config::process_owned_dependencies::validate_source_evidence(
            &field.source_evidence,
        )?;
    }
    ensure!(
        field.time.relative_to == TimeReference::PreserveRelative
            && parse_duration(&field.time.tolerance)?
                == crate::value_contract::time::DEFAULT_TOLERANCE.as_millis() as i64,
        "MySQL SQL times preserve request-relative differences with a fixed {}s tolerance",
        crate::value_contract::time::DEFAULT_TOLERANCE.as_secs()
    );
    Ok(())
}

pub(super) fn default_command() -> String {
    "COM_QUERY".into()
}

pub(super) fn is_default_command(command: &str) -> bool {
    command == "COM_QUERY"
}

#[cfg(test)]
pub(crate) fn validate_selector(mysql: &MysqlSelector) -> Result<()> {
    ensure!(
        mysql.params.is_empty(),
        "MySQL params and sql_values cannot be combined"
    );
    ensure!(
        matches!(mysql.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE"),
        "MySQL sql_values requires COM_QUERY or COM_STMT_EXECUTE"
    );
    let compiled = SqlValueTemplate::new(
        &mysql.sql,
        &mysql.tables,
        &mysql.table_patterns,
        mysql.table_series.as_ref(),
    )?;
    let template = compiled.tokens();
    ensure!(
        template
            .first()
            .is_some_and(|token| ["select", "update", "insert", "delete"]
                .iter()
                .any(|verb| token.is(verb))),
        "MySQL sql_values requires a SELECT, INSERT, UPDATE or DELETE template"
    );
    let count = template
        .iter()
        .filter(|t| **t == Token::Placeholder)
        .count();
    for (index, rule) in &mysql.sql_values {
        ensure!(
            *index < count,
            "MySQL sql_values[{index}] exceeds the {count} SQL template slots"
        );
        match rule {
            MysqlTimeValueRule::Scalar(field) => validate_time_field(field)?,
            MysqlTimeValueRule::Json(fields) => {
                ensure!(
                    !fields.is_empty(),
                    "MySQL sql_values[{index}].json must select at least one JSON Pointer"
                );
                for (pointer, field) in fields {
                    super::super::response::validate_json_pointer(pointer)
                        .context("invalid MySQL JSON time pointer")?;
                    ensure!(
                        !pointer.split('/').any(|segment| segment == "*"),
                        "MySQL JSON time pointers must be exact: {pointer:?}"
                    );
                    validate_time_field(field)?;
                }
                let pointers = fields.keys().collect::<Vec<_>>();
                for (position, left) in pointers.iter().enumerate() {
                    for right in &pointers[position + 1..] {
                        ensure!(
                            !super::super::response::response_locations_overlap(left, right),
                            "MySQL JSON time pointers overlap: {left:?} and {right:?}"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::runtime::sql_template::template_matches;
    use serde_json::json;

    #[test]
    fn table_templates_require_declared_identifier_bounds() {
        let valid = json!({"database":"app", "sql":"UPDATE {{table}} SET stamp=? WHERE {{table}}.id=?", "table_patterns":["subtasks_*"], "sql_values":{"0":{"time":"replay_now"}}});
        validate_selector(&serde_json::from_value(valid.clone()).unwrap()).unwrap();
        for (field, value) in [
            ("table_patterns", json!([])),
            ("table_patterns", json!(["*"])),
            ("table_patterns", json!(["subtasks_**"])),
            ("sql", json!("UPDATE subtasks_0155 SET stamp=? WHERE id=?")),
            ("sql", json!("UPDATE pre_{{table}} SET stamp=? WHERE id=?")),
            (
                "sql",
                json!("UPDATE subtasks SET stamp=?, note='{{table}}' WHERE id=?"),
            ),
            ("sql", json!("UPDATE subtasks SET {{table}}=? WHERE id=?")),
            (
                "sql",
                json!("UPDATE {{table}} SET stamp=? WHERE id=? /* {{table}} */"),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                validate_selector(&serde_json::from_value(invalid).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut series = valid.clone();
        series["table_patterns"] = json!([]);
        series["table_series"] = json!({"prefix":"subtasks_","start":0,"end":1023,"width":4});
        validate_selector(&serde_json::from_value(series.clone()).unwrap()).unwrap();
        series["table_series"]["end"] = json!(u32::MAX);
        assert!(validate_selector(&serde_json::from_value(series).unwrap()).is_err());
    }

    #[test]
    fn sql_value_slots_require_bounded_statements_and_explicit_time() {
        let valid = json!({"command":"COM_QUERY","sql":"UPDATE keys SET stamp=? WHERE id=?","params":{},"sql_values":{"0":{"source_evidence":"security.py:auth uses datetime.utcnow()","time":{"relative_to":"replay_now","tolerance":"5s"}}}});
        let selector: MysqlSelector = serde_json::from_value(valid.clone()).unwrap();
        validate_selector(&selector).unwrap();
        for (field, value) in [
            ("command", json!("COM_STMT_PREPARE")),
            ("sql", json!("DROP TABLE keys")),
            ("sql", json!("UPDATE keys SET stamp=?; DELETE FROM keys")),
            (
                "sql",
                json!("UPDATE keys SET stamp=? /*!50000 WHERE id=7 */"),
            ),
            ("sql", json!("UPDATE keys SET stamp='?' WHERE id=7")),
            (
                "params",
                json!({"0":{"time":{"relative_to":"replay_now","tolerance":"5s"}}}),
            ),
            (
                "sql_values",
                json!({"9":{"source_evidence":"security.py:auth uses now","time":{"relative_to":"replay_now","tolerance":"5s"}}}),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            let invalid: MysqlSelector = serde_json::from_value(invalid).unwrap();
            assert!(validate_selector(&invalid).is_err(), "{field}");
        }
        for sql in [
            "SELECT count(*) FROM keys WHERE stamp>? AND id=?",
            "SELECT id, stamp FROM keys WHERE stamp>? AND id=? ORDER BY id LIMIT 10",
        ] {
            let mut read = valid.clone();
            read["sql"] = json!(sql);
            validate_selector(&serde_json::from_value(read).unwrap()).unwrap();
        }
        assert!(template_matches(
            "UPDATE keys SET stamp=?, note='?' WHERE id=?",
            "UPDATE keys SET stamp='time', note='?' WHERE id=7"
        ));
        assert!(!template_matches(
            "UPDATE keys SET stamp=? WHERE id=?",
            "UPDATE keys SET stamp=now() WHERE id=7"
        ));
    }

    #[test]
    fn validates_exact_non_overlapping_json_time_pointers() {
        let valid = json!({
            "sql":"UPDATE kinds SET json=?, updated_at=? WHERE id=?",
            "sql_values":{
                "0":{"json":{
                    "/spec/observedAt":{"time":"replay_now","format":"%+"}
                }},
                "1":{"time":"replay_now"}
            }
        });
        let selector: MysqlSelector = serde_json::from_value(valid.clone()).unwrap();
        validate_selector(&selector).unwrap();

        for json_fields in [
            json!({"/spec":{"time":"replay_now"},"/spec/observedAt":{"time":"replay_now"}}),
            json!({"/spec/*":{"time":"replay_now"}}),
            json!({"spec/observedAt":{"time":"replay_now"}}),
        ] {
            let mut invalid = valid.clone();
            invalid["sql_values"]["0"]["json"] = json_fields;
            let selector: MysqlSelector = serde_json::from_value(invalid).unwrap();
            assert!(validate_selector(&selector).is_err());
        }
    }
}
