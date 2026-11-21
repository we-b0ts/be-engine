use super::*;

fn bindings(sql: &str) -> Vec<FieldBinding> {
    resolve(&super::super::tokens(sql).unwrap(), Some("app")).unwrap()
}

#[test]
fn one_physical_field_resolves_across_unconfigured_statement_shapes_and_clauses() {
    for sql in [
        "UPDATE tasks SET updated_at=?, title='stable' WHERE id=7",
        "INSERT INTO tasks(title,updated_at) VALUES('a',?),('b',?)",
        "INSERT INTO tasks SET updated_at=?, title='stable'",
        "SELECT id FROM tasks WHERE updated_at > ? ORDER BY id",
        "DELETE FROM tasks WHERE ? < updated_at",
        "SELECT count(*) FROM tasks WHERE updated_at BETWEEN ? AND ?",
        "SELECT id FROM tasks WHERE updated_at IN (?,?)",
        "SELECT a.id FROM tasks AS a JOIN jobs AS b ON a.updated_at > ? WHERE b.id=7",
        "SELECT updated_at FROM tasks GROUP BY updated_at HAVING updated_at > ?",
        "INSERT INTO tasks(id,updated_at) VALUES(7,?) ON DUPLICATE KEY UPDATE updated_at=?",
    ] {
        let bindings = bindings(sql);
        assert!(
            bindings
                .iter()
                .any(|b| b.field.table == "tasks" && b.field.column == "updated_at"),
            "{sql}: {bindings:?}"
        );
        assert!(
            bindings
                .iter()
                .all(|b| b.field.database.as_deref() == Some("app"))
        );
    }
}

#[test]
fn explicit_schema_and_aliases_retain_real_origin_and_ambiguous_fields_grant_nothing() {
    let bound = bindings(
        "SELECT t.id FROM archive.tasks AS t JOIN jobs j ON t.updated_at > ? WHERE j.updated_at > ? AND updated_at > ?",
    );
    assert_eq!(bound.len(), 2);
    assert_eq!(bound[0].field.database.as_deref(), Some("archive"));
    assert_eq!(bound[0].field.table, "tasks");
    assert_eq!(bound[1].field.table, "jobs");
    assert_eq!(bound[1].field.database.as_deref(), Some("app"));
    assert!(
        bindings("UPDATE tasks SET updated_at=DATE_ADD(updated_at, INTERVAL ? DAY)").is_empty()
    );
    assert!(
        resolve(
            &super::super::tokens(
                "SELECT id FROM tasks WHERE id IN (SELECT id FROM jobs WHERE updated_at > ?)"
            )
            .unwrap(),
            Some("app")
        )
        .is_none()
    );
}

#[test]
fn parser_keeps_original_token_positions_and_projected_aliases() {
    let sql = "UPDATE tasks SET payload='{\"id\":7}', updated_at=? WHERE updated_at BETWEEN ? AND ? AND id=7";
    let tokens = super::super::tokens(sql).unwrap();
    let bound = resolve(&tokens, Some("app")).unwrap();
    for occurrence in bound.iter().filter(|b| b.field.column == "updated_at") {
        assert_eq!(tokens[occurrence.token_index], Token::Placeholder);
    }
    let sql = super::super::tokens("SELECT t.updated_at AS changed, j.updated_at AS other FROM app.tasks t JOIN archive.jobs j ON t.id=j.id").unwrap();
    let origins = projection_columns(&sql, Some("default")).unwrap();
    assert_eq!(origins[0].0, "changed");
    assert_eq!(
        origins[0].1.as_ref().unwrap().database.as_deref(),
        Some("app")
    );
    assert_eq!(
        origins[1].1.as_ref().unwrap().database.as_deref(),
        Some("archive")
    );
    assert!(
        projection_columns(
            &super::super::tokens("SELECT * FROM tasks").unwrap(),
            Some("app")
        )
        .is_none()
    );
}

#[test]
fn native_null_binds_direct_values_and_remains_distinct_from_is_null_predicates() {
    for sql in [
        "UPDATE tasks SET updated_at=NULL WHERE id=7",
        "INSERT INTO tasks(updated_at,id) VALUES(NULL,7)",
        "SELECT id FROM tasks WHERE updated_at <=> NULL",
    ] {
        let tokens = super::super::tokens(sql).unwrap();
        let found = resolve(&tokens, Some("app")).unwrap();
        let field = found
            .iter()
            .find(|binding| binding.field.column == "updated_at")
            .unwrap();
        assert_eq!(tokens[field.token_index], Token::Null, "{sql}");
    }
    assert!(bindings("SELECT id FROM tasks WHERE updated_at IS NULL").is_empty());
    assert!(bindings("SELECT id FROM tasks WHERE updated_at IS NOT NULL").is_empty());
    for sql in [
        "UPDATE tasks SET updated_at=? WHERE completed_at IS NULL",
        "UPDATE tasks SET updated_at=? WHERE completed_at IS NOT NULL",
    ] {
        assert_eq!(
            bindings(sql).len(),
            1,
            "NULL grammar preserves other field bindings: {sql}"
        );
    }
}
