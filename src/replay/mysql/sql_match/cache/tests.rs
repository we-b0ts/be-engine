use super::*;
use crate::replay::mysql::{mysql_json, mysql_null};
use serde_json::json;

mod join_tests;
mod or_tests;
mod query_in_tests;
mod token_limit_tests;
mod truth_tests;
mod tuple_tests;

fn equal(a: &str, b: &str) -> bool {
    let mut cache = SqlCache::default();
    cache
        .get(a)
        .bind("COM_QUERY", None)
        .zip(cache.get(b).bind("COM_QUERY", None))
        .is_some_and(|(a, b)| a.matches(&b, false))
}

#[test]
fn mysql_predicates_match_in_lists_and_pure_conjunctions() {
    for (a, b) in [
        ("id IN (3,1,2)", "id IN (1,2,3)"),
        (
            "name NOT IN ('A','中文','b')",
            "name NOT IN ('b','A','中文')",
        ),
        ("id IN (NULL,2,1,1)", "id IN (1,2,NULL,1)"),
        (
            "id IN (18446744073709551615,-2,0)",
            "id IN (0,18446744073709551615,-2)",
        ),
        (
            "name IN ('O\\'Brien','a\\0b')",
            "name IN (X'610062','O''Brien')",
        ),
        ("a=1 AND (b=2 AND c IS NULL)", "(c IS NULL AND a=1) AND b=2"),
        (
            "a BETWEEN 1 AND 3 AND b IS NOT NULL",
            "b IS NOT NULL AND a BETWEEN 1 AND 3",
        ),
        (
            "a IN (2,1) AND b NOT IN ('b','a')",
            "b NOT IN ('a','b') AND a IN (1,2)",
        ),
    ] {
        assert!(
            equal(
                &format!("SELECT * FROM tasks WHERE {a}"),
                &format!("SELECT * FROM tasks WHERE {b}")
            ),
            "{a} vs {b}"
        );
    }
}

#[test]
fn mysql_predicates_reject_value_type_structure_and_scope_changes() {
    let source = "SELECT id FROM tasks WHERE uid=42 AND name IN ('AbC','def','def',NULL) ORDER BY id LIMIT 1";
    for actual in [
        "SELECT id FROM tasks WHERE name IN ('def','abc','def',NULL) AND uid=42 ORDER BY id LIMIT 1",
        "SELECT id FROM tasks WHERE name IN ('def','AbC',NULL) AND uid=42 ORDER BY id LIMIT 1",
        "SELECT id FROM tasks WHERE name IN ('def','AbC','def') AND uid=42 ORDER BY id LIMIT 1",
        "SELECT id FROM tasks WHERE name IN ('def','AbC','def',NULL) AND uid='42' ORDER BY id LIMIT 1",
        "SELECT id FROM other WHERE name IN ('def','AbC','def',NULL) AND uid=42 ORDER BY id LIMIT 1",
        "SELECT id FROM tasks WHERE name IN ('def','AbC','def',NULL) AND uid=42 ORDER BY id DESC LIMIT 1",
        "SELECT id FROM tasks WHERE name IN ('def','AbC','def',NULL) AND uid=42 ORDER BY id LIMIT 2",
        "SELECT id FROM tasks WHERE name NOT IN ('def','AbC','def',NULL) AND uid=42 ORDER BY id LIMIT 1",
        "SELECT id FROM tasks WHERE name IN ('def','AbC','def',NULL) OR uid=42 ORDER BY id LIMIT 1",
    ] {
        assert!(!equal(source, actual), "{actual}");
    }
    assert!(!equal(
        "SELECT * FROM tasks WHERE a=1 AND a=1",
        "SELECT * FROM tasks WHERE a=1"
    ));
}

#[test]
fn mysql_predicates_fail_closed_for_unproven_forms() {
    let mut cache = SqlCache::default();
    for sql in [
        "SELECT id FROM tasks WHERE id IN (1,'2')",
        "SELECT id FROM tasks WHERE id IN (1,RAND())",
        "SELECT id FROM tasks WHERE id IN (SELECT id FROM other)",
        "SELECT id FROM tasks WHERE id=1 OR custom_function()=2",
        "SELECT id FROM tasks WHERE @x:=1",
        "SELECT id FROM tasks WHERE 1/id>0 AND id<>0",
        "SELECT id FROM tasks WHERE id IN ()",
        "SELECT RAND() FROM tasks WHERE id IN (1,2)",
        "SELECT id FROM tasks WHERE id IN (1,2) ORDER BY FIELD(id,1,2)",
        "SELECT id FROM tasks WHERE id IN (1,2) FOR UPDATE",
        "SELECT id FROM tasks WHERE id IN (1,2) QUALIFY id=9",
        "SELECT ? FROM tasks WHERE id IN (1,2)",
        "SELECT id FROM tasks WHERE id IN (1,2) ORDER BY ?",
        "SELECT id FROM tasks WHERE id IN (1,2) ORDER BY 1.0",
        "SELECT id FROM tasks WHERE id IN (1,2) /*! AND uid=1 */",
        "SELECT /*+ BKA(tasks) */ id FROM tasks WHERE id IN (1,2)",
        "SELECT id FROM tasks WHERE id IN (1,2); SELECT 1",
        "UPDATE tasks SET uid=1 WHERE id IN (1,2)",
    ] {
        assert!(cache.get(sql).bind("COM_QUERY", None).is_none(), "{sql}");
    }
    let deeply_nested = format!(
        "SELECT id FROM tasks WHERE {}id=1{}",
        "(".repeat(100),
        ")".repeat(100)
    );
    assert!(cache.get(&deeply_nested).bind("COM_QUERY", None).is_none());
    for sql in [
        "SELECT ? FROM tasks WHERE id IN (1,2)",
        "SELECT id FROM tasks WHERE id IN (1,2) ORDER BY ?",
    ] {
        assert!(cache.get(sql).metadata().is_none(), "{sql}");
    }
}

#[test]
fn sql_cache_binds_each_execution_before_sorting_and_preserves_metadata_constants() {
    let mut cache = SqlCache::default();
    let source = cache
        .get("SELECT id FROM tasks WHERE uid=42 AND name IN ('AbC','def',NULL)")
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get("SELECT id FROM tasks WHERE name IN (?,?,?) AND uid=?");
    let params = [
        mysql_json("string", json!("def")),
        mysql_null(),
        mysql_json("string", json!("AbC")),
        mysql_json("integer", json!(42)),
    ];
    assert!(target.metadata().unwrap().matches(&source, true));
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false)
    );
    let mut wrong = params.clone();
    wrong.swap(0, 3);
    assert!(target.bind("COM_STMT_EXECUTE", Some(&wrong)).is_none());
    wrong = params.clone();
    wrong[3] = mysql_json("integer", json!(43));
    assert!(
        !target
            .bind("COM_STMT_EXECUTE", Some(&wrong))
            .unwrap()
            .matches(&source, false)
    );
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params[..3]))
            .is_none()
    );
    assert!(target.bind("COM_STMT_EXECUTE", None).is_none());
    assert!(target.bind("COM_QUERY", None).is_none());
    assert!(
        !cache
            .get("SELECT id FROM tasks WHERE name IN ('wrong',?,?) AND uid=?")
            .metadata()
            .unwrap()
            .matches(&source, true)
    );
    // Ambiguous-looking repeated predicates need a complete matching, with
    // fixed literals retained even when the template has additional holes.
    let source = cache
        .get("SELECT id FROM tasks WHERE id IN (1,2) AND id IN (2,3)")
        .bind("COM_QUERY", None)
        .unwrap();
    assert!(
        cache
            .get("SELECT id FROM tasks WHERE id IN (?,2) AND id IN (1,?)")
            .metadata()
            .unwrap()
            .matches(&source, true)
    );
}

#[test]
fn sql_cache_reuses_constants_and_failed_parses_and_bounds_retention() {
    let mut cache = SqlCache::default();
    let sql = "SELECT id FROM tasks WHERE id IN (1,2)";
    let compiled = cache.get(sql);
    assert!(Arc::ptr_eq(&compiled, &cache.get(sql)));
    assert!(Arc::ptr_eq(
        &compiled.bind("COM_QUERY", None).unwrap(),
        &compiled.bind("COM_QUERY", None).unwrap()
    ));
    let invalid = cache.get("SELECT /*! unsupported */ 1");
    assert!(Arc::ptr_eq(
        &invalid,
        &cache.get("SELECT /*! unsupported */ 1")
    ));
    assert_eq!(cache.compilations, 2);
    for id in 0..MAX_ENTRIES {
        cache.get(&format!("SELECT id FROM tasks WHERE id={id}"));
    }
    assert_eq!(cache.entries.len(), MAX_ENTRIES);
    assert!(!Arc::ptr_eq(&compiled, &cache.get(sql)));
    assert!(cache.bytes <= MAX_SQL_BYTES);
    let large = "x".repeat(MAX_SINGLE_SQL_BYTES + 1);
    assert!(cache.get(&large).bind("COM_QUERY", None).is_none());
    assert!(!cache.entries.contains_key(&large));
    for id in 0..40 {
        cache.get(&format!(
            "{}SELECT id FROM tasks WHERE id={id}",
            " ".repeat(32 * 1024)
        ));
    }
    assert!(cache.bytes <= MAX_SQL_BYTES);
    assert!(
        cache.entries.len() < 40,
        "the byte budget must evict entries before the count limit"
    );
}

#[test]
fn cached_large_in_lists_keep_every_value_without_reparsing() {
    let mut cache = SqlCache::default();
    let values = (0..1000)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let source = cache
        .get(&format!("SELECT id FROM tasks WHERE id IN ({values})"))
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get(&format!(
        "SELECT id FROM tasks WHERE id IN ({})",
        vec!["?"; 1000].join(",")
    ));
    let mut params = (0..1000)
        .rev()
        .map(|v| mysql_json("integer", json!(v)))
        .collect::<Vec<_>>();
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false)
    );
    params[0] = mysql_json("integer", json!(1000));
    assert!(
        !target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false)
    );
    assert!(target.metadata().unwrap().matches(&source, true));
    assert_eq!(cache.compilations, 2);
}
