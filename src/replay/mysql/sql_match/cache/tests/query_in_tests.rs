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

fn teams_union_query(
    native_restricted: &str,
    visible_namespaces: &str,
    shared_restricted: &str,
    entity_ids: &str,
    excluded_namespaces: &str,
) -> String {
    format!(
        "SELECT anon_1.team_id, anon_1.restricted_guest_access \
         FROM (SELECT combined_teams.team_id, combined_teams.restricted_guest_access, \
           row_number() OVER (PARTITION BY combined_teams.team_id \
             ORDER BY combined_teams.access_rank ASC, combined_teams.team_id DESC) AS access_row_number \
           FROM (SELECT kinds.id AS team_id, \
                    kinds.namespace IN ({native_restricted}) AS restricted_guest_access, \
                    0 AS access_rank \
                 FROM kinds \
                 WHERE kinds.kind = 'Team' AND kinds.namespace IN ({visible_namespaces}) \
                 UNION ALL \
                 SELECT kinds.id AS team_id, \
                    namespace.name IN ({shared_restricted}) AS restricted_guest_access, \
                    2 AS access_rank \
                 FROM kinds \
                 INNER JOIN resource_members \
                   ON resource_members.resource_id = kinds.id \
                  AND resource_members.resource_type IN ('Team','TEAM') \
                 INNER JOIN namespace \
                   ON CAST(resource_members.entity_id AS SIGNED INTEGER) = namespace.id \
                 WHERE resource_members.entity_id IN ({entity_ids}) \
                   AND kinds.namespace NOT IN ({excluded_namespaces})) AS combined_teams) AS anon_1 \
         WHERE anon_1.access_row_number = 1 \
         ORDER BY anon_1.team_id DESC LIMIT 0, 100"
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
fn union_join_and_projection_in_lists_match_as_atomic_multisets() {
    let source = teams_union_query(
        "'restricted-b','restricted-a','restricted-a'",
        "'visible-b','visible-a'",
        "'restricted-b','restricted-a','restricted-a'",
        "'20','10'",
        "'visible-b','visible-a'",
    );
    let reordered = teams_union_query(
        "'restricted-a','restricted-b','restricted-a'",
        "'visible-a','visible-b'",
        "'restricted-a','restricted-a','restricted-b'",
        "'10','20'",
        "'visible-a','visible-b'",
    );
    assert!(equal(&source, &reordered));

    let mut cache = SqlCache::default();
    let recorded = cache.get(&source).bind("COM_QUERY", None).unwrap();
    let prepared = cache.get(&teams_union_query("?,?,?", "?,?", "?,?,?", "?,?", "?,?"));
    assert!(prepared.metadata().unwrap().matches(&recorded, true));
    let mut params = [
        "restricted-a",
        "restricted-b",
        "restricted-a",
        "visible-a",
        "visible-b",
        "restricted-a",
        "restricted-a",
        "restricted-b",
        "10",
        "20",
        "visible-a",
        "visible-b",
    ]
    .map(|value| mysql_json("string", json!(value)));
    assert!(
        prepared
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
    params[7] = mysql_json("string", json!("restricted-c"));
    assert!(
        !prepared
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
}

#[test]
fn union_in_matching_keeps_every_other_query_node_strict() {
    let source = teams_union_query(
        "'restricted-b','restricted-a','restricted-a'",
        "'visible-b','visible-a'",
        "'restricted-b','restricted-a','restricted-a'",
        "'20','10'",
        "'visible-b','visible-a'",
    );
    for changed in [
        source.replacen("UNION ALL", "UNION", 1),
        source.replacen(
            "resource_members.resource_id = kinds.id",
            "resource_members.resource_id = kinds.user_id",
            1,
        ),
        source.replacen(
            "kinds.namespace IN ('restricted-b','restricted-a','restricted-a')",
            "kinds.namespace NOT IN ('restricted-b','restricted-a','restricted-a')",
            1,
        ),
        source.replacen(
            "ORDER BY anon_1.team_id DESC",
            "ORDER BY anon_1.team_id ASC",
            1,
        ),
        source.replacen("LIMIT 0, 100", "LIMIT 0, 99", 1),
        source.replacen(
            "namespace.name IN ('restricted-b','restricted-a','restricted-a')",
            "namespace.name IN ('restricted-b','restricted-a')",
            1,
        ),
    ] {
        assert!(!equal(&source, &changed), "{changed}");
    }
}

#[test]
fn nested_in_compatibility_rejects_unscoped_or_complex_subqueries() {
    let mut cache = SqlCache::default();
    for sql in [
        "SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) AND EXISTS (SELECT 1 FROM members WHERE members.kind_id=kinds.id AND members.entity_id IN ('b','a'))",
        "SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) OR EXISTS (SELECT 1 FROM (SELECT * FROM members) AS members WHERE members.kind_id=kinds.id AND members.entity_id IN ('b','a'))",
        "SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) OR kinds.id IN (SELECT kind_id FROM members)",
        "WITH visible AS (SELECT kind_id FROM members) SELECT kinds.id FROM kinds WHERE kinds.id IN (2,1) OR EXISTS (SELECT 1 FROM visible WHERE visible.kind_id=kinds.id)",
    ] {
        assert!(cache.get(sql).bind("COM_QUERY", None).is_none(), "{sql}");
    }
}

#[test]
fn derived_counts_and_joined_exists_preserve_full_query_identity() {
    let source = nested_query("3,1,2", "'b','a','a'", "'Owner','Developer'");
    let target = nested_query("2,3,1", "'a','b','a'", "'Developer','Owner'");
    for (source, target) in [
        (
            format!("SELECT count(*) AS total FROM ({source}) AS items"),
            format!("SELECT count(*) AS total FROM ({target}) AS items"),
        ),
        (
            source.replacen(
                "FROM kinds",
                "FROM kinds INNER JOIN namespace ON namespace.name=kinds.namespace",
                1,
            ),
            target.replacen(
                "FROM kinds",
                "FROM kinds INNER JOIN namespace ON namespace.name=kinds.namespace",
                1,
            ),
        ),
        (
            source.replace(
                "FROM resource_members",
                "FROM resource_members JOIN users ON users.id=resource_members.user_id",
            ),
            target.replace(
                "FROM resource_members",
                "FROM resource_members JOIN users ON users.id=resource_members.user_id",
            ),
        ),
        (
            format!("{source} ORDER BY kinds.id DESC LIMIT 10"),
            format!("{target} ORDER BY kinds.id DESC LIMIT 10"),
        ),
    ] {
        assert!(equal(&source, &target), "{source}");
        for changed in [
            target.replace("'Developer','Owner'", "'Developer','Guest'"),
            target.replace("'a','b','a'", "'a','b'"),
            target.replace(
                "resource_members.resource_id = kinds.id",
                "resource_members.resource_id = kinds.user_id",
            ),
            target.replace("FROM resource_members", "FROM other_members"),
            target.replace("kinds.id IN", "kinds.id NOT IN"),
            format!("{target} FOR UPDATE"),
        ] {
            assert!(!equal(&source, &changed), "{changed}");
        }
    }
}

#[test]
fn derived_count_templates_bind_fresh_values_and_keep_wrapper_exact() {
    let source = "SELECT count(*) AS total FROM (SELECT id FROM tasks WHERE name IN ('b','a','a') AND id IN (2,1)) AS items";
    let target = "SELECT count(*) AS total FROM (SELECT id FROM tasks WHERE name IN (?,?,?) AND id IN (?,?)) AS items";
    let mut cache = SqlCache::default();
    let recorded = cache.get(source).bind("COM_QUERY", None).unwrap();
    let prepared = cache.get(target);
    assert!(prepared.metadata().unwrap().matches(&recorded, true));
    let mut params = [
        mysql_json("string", json!("a")),
        mysql_json("string", json!("b")),
        mysql_json("string", json!("a")),
        mysql_json("integer", json!(1)),
        mysql_json("integer", json!(2)),
    ];
    assert!(
        prepared
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
    params[1] = mysql_json("string", json!("c"));
    assert!(
        !prepared
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
    for changed in [
        source.replace("count(*)", "count(id)"),
        source.replace("AS total", "AS other"),
        source.replace("AS items", "AS other"),
        source.replace("(2,1)", "(2,'1')"),
    ] {
        assert!(!equal(source, &changed), "{changed}");
    }
}
