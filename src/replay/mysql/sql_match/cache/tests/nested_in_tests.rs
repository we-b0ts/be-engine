use super::*;
use serde_json::json;

fn nested_query(ids: &str, entities: &str, roles: &str) -> String {
    format!(
        "SELECT kinds.id AS kinds_id FROM kinds \
         WHERE kinds.id IN ({ids}) AND (\
           coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = '' \
           OR coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = 'edit' \
              AND (kinds.user_id = 559 OR EXISTS (\
                SELECT 1 FROM resource_members \
                WHERE resource_members.resource_type IN ('KnowledgeBase','KNOWLEDGE_BASE') \
                  AND resource_members.resource_id = kinds.id \
                  AND resource_members.entity_type = 'namespace' \
                  AND resource_members.entity_id IN ({entities}) \
                  AND resource_members.role IN ({roles})\
              ))\
         ) AND NOT EXISTS (\
           SELECT 1 FROM resource_members \
           WHERE resource_members.resource_id = kinds.id \
             AND resource_members.role = 'RestrictedAnalyst'\
         )"
    )
}

#[test]
fn nested_exists_in_lists_match_as_atomic_multisets() {
    let source = nested_query(
        "3,1,2,2",
        "'dept-b','dept-a','dept-a'",
        "'Owner','Maintainer','Developer'",
    );
    let target = nested_query(
        "2,3,2,1",
        "'dept-a','dept-a','dept-b'",
        "'Developer','Owner','Maintainer'",
    );
    assert!(equal(&source, &target));

    let source = source.replace(
        "resource_members.role IN ('Owner','Maintainer','Developer')",
        "resource_members.role NOT IN ('Guest','Restricted')",
    );
    let target = target.replace(
        "resource_members.role IN ('Developer','Owner','Maintainer')",
        "resource_members.role NOT IN ('Restricted','Guest')",
    );
    assert!(equal(&source, &target));
}

#[test]
fn knowledge_base_access_query_matches_every_reordered_list() {
    let source = r#"SELECT kinds.id AS kinds_id
FROM kinds
WHERE kinds.id IN (178418, 139590, 230242, 224035, 216471, 145000, 139901)
  AND (
    coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = ''
    OR coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = 'read'
    OR coalesce(json_unquote(json_extract(kinds.json, '$.spec.directAccessRequirement')), '') = 'edit'
       AND (
         kinds.user_id = 559
         OR EXISTS (
           SELECT 1 FROM resource_members
           WHERE resource_members.resource_type IN ('KnowledgeBase', 'KNOWLEDGE_BASE')
             AND resource_members.resource_id = kinds.id
             AND resource_members.status IN ('approved', 'APPROVED')
             AND resource_members.entity_type = 'user'
             AND resource_members.entity_id = '559'
             AND resource_members.`role` IN ('Owner', 'Maintainer', 'Developer')
         )
         OR EXISTS (
           SELECT 1 FROM resource_members
           WHERE resource_members.resource_type IN ('KnowledgeBase', 'KNOWLEDGE_BASE')
             AND resource_members.resource_id = kinds.id
             AND resource_members.status IN ('approved', 'APPROVED')
             AND resource_members.entity_type = 'namespace'
             AND resource_members.entity_id IN ('557', '569', '509', '245')
             AND resource_members.`role` IN ('Owner', 'Maintainer', 'Developer')
         )
         OR kinds.namespace IN ('Paladin-Robot')
       )
  )
  AND NOT EXISTS (
    SELECT 1 FROM resource_members
    WHERE resource_members.resource_type IN ('KnowledgeBase', 'KNOWLEDGE_BASE')
      AND resource_members.resource_id = kinds.id
      AND resource_members.status IN ('approved', 'APPROVED')
      AND resource_members.entity_type = 'user'
      AND resource_members.entity_id = '559'
      AND resource_members.`role` = 'RestrictedAnalyst'
  )"#;
    let target = source
        .replace(
            "178418, 139590, 230242, 224035, 216471, 145000, 139901",
            "139901, 216471, 178418, 145000, 224035, 230242, 139590",
        )
        .replace(
            "'KnowledgeBase', 'KNOWLEDGE_BASE'",
            "'KNOWLEDGE_BASE', 'KnowledgeBase'",
        )
        .replace("'approved', 'APPROVED'", "'APPROVED', 'approved'")
        .replace(
            "'Owner', 'Maintainer', 'Developer'",
            "'Developer', 'Owner', 'Maintainer'",
        )
        .replace("'557', '569', '509', '245'", "'245', '509', '557', '569'");
    assert!(equal(source, &target));
}

#[test]
fn nested_exists_matching_keeps_every_non_order_semantic_strict() {
    let source = nested_query(
        "3,1,2",
        "'dept-b','dept-a','dept-a'",
        "'Owner','Maintainer','Developer'",
    );
    for target in [
        nested_query(
            "3,1,2",
            "'dept-b','dept-a'",
            "'Owner','Maintainer','Developer'",
        ),
        nested_query(
            "3,1,4",
            "'dept-b','dept-a','dept-a'",
            "'Owner','Maintainer','Developer'",
        ),
        nested_query(
            "3,1,2",
            "'dept-b','dept-a','dept-a'",
            "'Owner','Maintainer','Guest'",
        ),
        nested_query(
            "3,1,2",
            "'dept-b','dept-a','dept-a'",
            "'Owner','Maintainer','Developer'",
        )
        .replace("FROM resource_members", "FROM other_members"),
        nested_query(
            "3,1,2",
            "'dept-b','dept-a','dept-a'",
            "'Owner','Maintainer','Developer'",
        )
        .replace(
            "resource_members.resource_id = kinds.id",
            "resource_members.resource_id = kinds.user_id",
        ),
        nested_query(
            "3,1,2",
            "'dept-b','dept-a','dept-a'",
            "'Owner','Maintainer','Developer'",
        )
        .replace("$.spec.directAccessRequirement", "$.spec.other"),
        nested_query(
            "3,1,2",
            "'dept-b','dept-a','dept-a'",
            "'Owner','Maintainer','Developer'",
        )
        .replacen("entity_id IN", "entity_id NOT IN", 1),
    ] {
        assert!(!equal(&source, &target), "{target}");
    }
}

#[test]
fn nested_exists_templates_bind_prepared_values_and_metadata() {
    let mut cache = SqlCache::default();
    let source = cache
        .get(&nested_query(
            "3,1,2",
            "'dept-b','dept-a'",
            "'Owner','Maintainer','Developer'",
        ))
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get(&nested_query(
        "?,?,?",
        "?,?",
        "'Developer','Owner','Maintainer'",
    ));
    assert!(target.metadata().unwrap().matches(&source, true));

    let params = [
        mysql_json("integer", json!(2)),
        mysql_json("integer", json!(3)),
        mysql_json("integer", json!(1)),
        mysql_json("string", json!("dept-a")),
        mysql_json("string", json!("dept-b")),
    ];
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false)
    );
    let mut wrong = params.clone();
    wrong[4] = mysql_json("string", json!("dept-c"));
    assert!(
        !target
            .bind("COM_STMT_EXECUTE", Some(&wrong))
            .unwrap()
            .matches(&source, false)
    );
    let mut mixed = params;
    mixed[4] = mysql_json("integer", json!(9));
    assert!(target.bind("COM_STMT_EXECUTE", Some(&mixed)).is_none());
}

#[test]
fn nested_in_compatibility_rejects_unscoped_or_complex_subqueries() {
    let mut cache = SqlCache::default();
    for sql in [
        "SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) AND EXISTS (SELECT 1 FROM members WHERE members.kind_id=kinds.id AND members.entity_id IN ('b','a'))",
        "SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) OR EXISTS (SELECT 1 FROM members JOIN users ON users.id=members.user_id WHERE members.kind_id=kinds.id AND members.entity_id IN ('b','a'))",
        "SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) OR kinds.id IN (SELECT kind_id FROM members)",
        "WITH visible AS (SELECT kind_id FROM members) SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) OR EXISTS (SELECT 1 FROM visible WHERE visible.kind_id=kinds.id)",
    ] {
        assert!(cache.get(sql).bind("COM_QUERY", None).is_none(), "{sql}");
    }
}
