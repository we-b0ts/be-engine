//! Physical field selection shared by live SQL matching and immutable evidence.
use super::*;

/// A driver may inline some values while binding others. Parameter ordinal is
/// local to that statement; only the same physical SQL value position can
/// supply a paired native kind. Binding completeness remains mandatory on
/// both sides, including an inline prepared statement with zero parameters.
pub(super) fn materialized_pair(
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    target_sql: Option<&str>,
    target_params: Option<&[RecordedMysqlValue]>,
) -> Result<(Vec<Token>, Vec<Token>)> {
    let statement = |sql: Option<&str>| {
        sql.and_then(crate::mysql::sql::bounds::statement)
            .context("invalid, absent or oversized MySQL SQL")
    };
    let source = statement(source_sql)?;
    let target = statement(target_sql)?;
    ensure!(source.len() == target.len(), "SQL token inventory changed");
    let source_params = source_params.unwrap_or_default();
    let target_params = target_params.unwrap_or_default();
    let mut source_bound = source_params.iter();
    let mut target_bound = target_params.iter();
    for (source, target) in source.iter().zip(&target) {
        let source = (*source == Token::Placeholder)
            .then(|| source_bound.next())
            .flatten();
        let target = (*target == Token::Placeholder)
            .then(|| target_bound.next())
            .flatten();
        if let (Some(source), Some(target)) = (source, target) {
            ensure!(
                source.kind == target.kind,
                "MySQL prepared parameter kind changed"
            );
        }
    }
    let materialize = |tokens, params| {
        crate::protocols::replay::mysql::sql_match::materialize_tokens(tokens, params)
            .context("MySQL SQL parameters are incomplete or invalid")
    };
    Ok((
        materialize(source, source_params)?,
        materialize(target, target_params)?,
    ))
}

pub(crate) fn scalar(token: &Token) -> Result<Value> {
    match token {
        Token::Bytes(bytes) => Ok(Value::String(
            String::from_utf8(bytes.clone())
                .context("SQL scalar must retain UTF-8 string identity")?,
        )),
        Token::Number(number) => {
            crate::json_value::parse(number.as_bytes()).context("invalid SQL native number")
        }
        Token::Null => Ok(Value::Null),
        _ => anyhow::bail!("selected SQL scalar is not a complete native value"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn binding_layout_is_statement_local_but_paired_native_kinds_stay_strict() {
        let source = "UPDATE tasks SET stamp=? WHERE id=?";
        let params: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
            {"kind":"datetime","value":"2020-01-01 00:00:00.123456"},
            {"kind":"integer","value":7}
        ]))
        .unwrap();
        for (target, target_params) in [
            (
                "UPDATE tasks SET stamp='2020-01-01 00:00:00.123456' WHERE id=7",
                vec![],
            ),
            (
                "UPDATE tasks SET stamp='2020-01-01 00:00:00.123456' WHERE id=?",
                vec![params[1].clone()],
            ),
            (
                "UPDATE tasks SET stamp=? WHERE id=7",
                vec![params[0].clone()],
            ),
        ] {
            let (source, target) = materialized_pair(
                Some(source),
                Some(&params),
                Some(target),
                Some(&target_params),
            )
            .unwrap();
            assert_eq!(source, target);
        }
        let mut changed = params.clone();
        changed[0].kind = "string".into();
        assert!(
            materialized_pair(Some(source), Some(&params), Some(source), Some(&changed)).is_err()
        );
        assert!(
            materialized_pair(
                Some(source),
                Some(&params[..1]),
                Some(source),
                Some(&params)
            )
            .is_err()
        );
        assert!(
            materialized_pair(
                Some(source),
                Some(&params),
                Some(source),
                Some(&params[..1])
            )
            .is_err()
        );
    }
}
