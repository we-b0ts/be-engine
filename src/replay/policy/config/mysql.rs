//! Configuration validation for explicit MySQL SQL time slots.
use super::*;
use crate::mysql::sql::Token;
use crate::replay::policy::sql_template::bounded_tokens;

fn validate_time_field(field: &MysqlTimeFieldRule) -> Result<()> {
    if !field.source_evidence.is_empty() {
        crate::config::process_owned_dependencies::validate_source_evidence(
            &field.source_evidence,
        )?;
    }
    parse_duration(&field.time.offset).context("invalid time.offset")?;
    ensure!(
        parse_duration(&field.time.tolerance)? >= 0,
        "time.tolerance must not be negative"
    );
    if let Some(timezone) = &field.time.timezone {
        parse_timezone(timezone)?;
    }
    Ok(())
}

pub(super) fn default_command() -> String {
    "COM_QUERY".into()
}

pub(super) fn is_default_command(command: &str) -> bool {
    command == "COM_QUERY"
}

pub(in crate::replay::policy) fn validate_selector(mysql: &MysqlSelector) -> Result<()> {
    ensure!(
        mysql.params.is_empty(),
        "MySQL params and sql_values cannot be combined"
    );
    ensure!(
        matches!(mysql.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE"),
        "MySQL sql_values requires COM_QUERY or COM_STMT_EXECUTE"
    );
    let template = bounded_tokens(&mysql.sql).context("invalid or oversized MySQL SQL template")?;
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
    use crate::replay::policy::sql_template::template_matches;
    use serde_json::json;

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
