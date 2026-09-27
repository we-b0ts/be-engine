use super::*;

fn models_query(branches: &str) -> String {
    format!(
        "SELECT resource_members.entity_type AS resource_members_entity_type, \
         resource_members.entity_id AS resource_members_entity_id, kinds.id AS kinds_id, \
         kinds.name AS kinds_name FROM resource_members \
         INNER JOIN kinds ON kinds.id = resource_members.resource_id \
         WHERE resource_members.resource_type = 'Model' \
           AND resource_members.status = 'approved' \
           AND ({branches}) \
           AND kinds.kind = 'Model' AND kinds.user_id != 0 \
           AND kinds.is_active IS true ORDER BY kinds.id"
    )
}

#[test]
fn join_query_matches_reordered_pure_where_branches_after_binding() {
    let source = models_query(
        "resource_members.entity_type = 'user' \
         AND resource_members.entity_id IN ('358') \
         OR resource_members.entity_type = 'namespace' \
         AND resource_members.entity_id IN ('452', '464', '92')",
    );
    let target = models_query(
        "resource_members.entity_type = 'namespace' \
         AND resource_members.entity_id IN (?, ?, ?) \
         OR resource_members.entity_type = 'user' \
         AND resource_members.entity_id IN (?)",
    );
    let mut cache = SqlCache::default();
    let recorded = cache.get(&source).bind("COM_QUERY", None).unwrap();
    let target = cache.get(&target);
    assert!(target.metadata().unwrap().matches(&recorded, true));
    let params = [
        mysql_json("string", json!("452")),
        mysql_json("string", json!("464")),
        mysql_json("string", json!("92")),
        mysql_json("string", json!("358")),
    ];
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
}

#[test]
fn join_query_keeps_every_non_predicate_and_predicate_value_strict() {
    let source = models_query(
        "resource_members.entity_type = 'user' \
         AND resource_members.entity_id IN ('358') \
         OR resource_members.entity_type = 'namespace' \
         AND resource_members.entity_id IN ('452', '464', '92')",
    );
    let reordered = models_query(
        "resource_members.entity_type = 'namespace' \
         AND resource_members.entity_id IN ('92', '452', '464') \
         OR resource_members.entity_type = 'user' \
         AND resource_members.entity_id IN ('358')",
    );
    assert!(equal(&source, &reordered));
    for changed in [
        reordered.replacen(
            "kinds.id = resource_members.resource_id",
            "kinds.user_id = resource_members.resource_id",
            1,
        ),
        reordered.replacen("kinds.name AS kinds_name", "kinds.json AS kinds_json", 1),
        reordered.replacen("ORDER BY kinds.id", "ORDER BY kinds.id DESC", 1),
        reordered.replacen("resource_type = 'Model'", "resource_type = 'Shell'", 1),
        reordered.replacen("entity_id IN ('358')", "entity_id IN ('359')", 1),
        reordered.replacen("entity_type = 'user'", "entity_type = 'namespace'", 1),
    ] {
        assert!(!equal(&source, &changed), "{changed}");
    }
}

#[test]
fn join_query_rejects_unproven_where_expressions() {
    let mut cache = SqlCache::default();
    for predicate in [
        "resource_members.entity_type = 'user' OR RAND() > 0",
        "resource_members.entity_type = 'user' OR EXISTS (SELECT 1 FROM users)",
        "resource_members.entity_type = 'user' OR 1 / kinds.id > 0",
    ] {
        let sql = models_query(predicate);
        assert!(cache.get(&sql).bind("COM_QUERY", None).is_none(), "{sql}");
    }
}
