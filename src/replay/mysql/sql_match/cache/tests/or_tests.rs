use super::*;

#[test]
fn or_groups_preserve_pairing_duplicates_nulls_and_boolean_structure() {
    for (a, b) in [
        ("a=1 OR (b=2 OR c IS NULL)", "(c IS NULL OR a=1) OR b=2"),
        (
            "(a=1 AND b=2) OR (a=3 AND b=4)",
            "(b=4 AND a=3) OR (b=2 AND a=1)",
        ),
        (
            "tenant=7 AND (a=1 OR b IN (3,2))",
            "(b IN (2,3) OR a=1) AND tenant=7",
        ),
        (
            "(a,b) IN ((1,2),(3,4)) OR c IS NULL",
            "c IS NULL OR (a,b) IN ((3,4),(1,2))",
        ),
        ("a <=> NULL OR a=1 OR a=1", "a=1 OR a <=> NULL OR a=1"),
        (
            "a BETWEEN 1 AND 3 OR b NOT IN (1,2)",
            "b NOT IN (2,1) OR a BETWEEN 1 AND 3",
        ),
    ] {
        assert!(
            equal(
                &format!("SELECT id FROM tasks WHERE {a}"),
                &format!("SELECT id FROM tasks WHERE {b}")
            ),
            "{a} vs {b}"
        );
    }
    for (a, b) in [
        (
            "(a=1 AND b=2) OR (a=3 AND b=4)",
            "(a=1 AND b=4) OR (a=3 AND b=2)",
        ),
        ("a=1 AND (b=2 OR c=3)", "(a=1 AND b=2) OR c=3"),
        ("a=1 OR b=2", "a=1 AND b=2"),
        ("a=1 OR a=1", "a=1"),
        ("a=1 OR a=1 OR b=2", "a=1 OR b=2 OR b=2"),
        ("a=1 OR b IS NULL", "a=1 OR b=NULL"),
        ("a=1 OR b='A'", "b='a' OR a=1"),
        ("a=1 OR b=2", "b=2 OR a='1'"),
        // No distributivity or absorption, even where algebra would permit it.
        ("a=1 AND (b=2 OR c=3)", "(a=1 AND b=2) OR (a=1 AND c=3)"),
    ] {
        assert!(
            !equal(
                &format!("SELECT id FROM tasks WHERE {a}"),
                &format!("SELECT id FROM tasks WHERE {b}")
            ),
            "{a} vs {b}"
        );
    }
}

#[test]
fn or_metadata_uses_injective_branch_matching_and_keeps_fixed_values() {
    let mut cache = SqlCache::default();
    let source = cache
        .get("SELECT id FROM tasks WHERE (a=1 AND b=2) OR (a=3 AND b=2)")
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get("SELECT id FROM tasks WHERE (b=2 AND a=?) OR (b=? AND a=1)");
    assert!(
        target.metadata().unwrap().matches(&source, true),
        "fixed branch needs the first source branch; greedy matching fails"
    );
    for (values, expected) in [([3, 2], true), ([2, 3], false), ([1, 2], false)] {
        let params = values.map(|v| mysql_json("integer", json!(v)));
        assert_eq!(
            target
                .bind("COM_STMT_EXECUTE", Some(&params))
                .unwrap()
                .matches(&source, false),
            expected
        );
    }
    for sql in [
        "SELECT id FROM tasks WHERE (a=1 AND b=?) OR (a=1 AND b=?)",
        "SELECT id FROM tasks WHERE (a=? AND b=9) OR (a=1 AND b=?)",
    ] {
        assert!(
            !cache.get(sql).metadata().unwrap().matches(&source, true),
            "{sql}"
        );
    }
}

#[test]
fn repeated_nested_boolean_templates_use_linear_metadata_matching() {
    // Each node is locally small, but their pairwise comparisons multiply.
    fn tree(depth: usize, leaf: &str) -> String {
        if depth == 0 {
            return format!("a={leaf}");
        }
        let child = tree(depth - 1, leaf);
        let op = if depth.is_multiple_of(2) { "AND" } else { "OR" };
        format!("({child} {op} {child})")
    }
    let mut cache = SqlCache::default();
    let source = cache
        .get(&format!("SELECT id FROM tasks WHERE {}", tree(7, "1")))
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get(&format!("SELECT id FROM tasks WHERE {}", tree(7, "?")));
    assert!(target.metadata().unwrap().matches(&source, true));
    let params = vec![mysql_json("integer", json!(1)); 128];
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false),
        "bound values need no combinatorial assignment"
    );
}

#[test]
fn large_or_templates_preserve_empty_null_duplicate_values_and_fixed_constraints() {
    for size in [63, 64, 65, 79, 128, 256] {
        let mut cache = SqlCache::default();
        let branches = (0..size)
            .map(|i| format!("(user_id={i} AND name='' AND namespace='default')"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let source = cache
            .get(&format!("SELECT id FROM kinds WHERE {branches}"))
            .bind("COM_QUERY", None)
            .unwrap();
        let target = cache.get(&format!(
            "SELECT id FROM kinds WHERE {}",
            vec!["(name=? AND namespace='default' AND user_id=?)"; size].join(" OR ")
        ));
        assert!(target.metadata().unwrap().matches(&source, true), "{size}");
        let mut params = (0..size)
            .rev()
            .flat_map(|i| {
                [
                    mysql_json("string", json!("")),
                    mysql_json("integer", json!(i)),
                ]
            })
            .collect::<Vec<_>>();
        assert!(
            target
                .bind("COM_STMT_EXECUTE", Some(&params))
                .unwrap()
                .matches(&source, false),
            "{size}"
        );
        params[0] = mysql_null();
        assert!(
            !target
                .bind("COM_STMT_EXECUTE", Some(&params))
                .unwrap()
                .matches(&source, false),
            "NULL is not an empty string"
        );
        params[0] = mysql_json("string", json!(""));
        params[1] = params[3].clone();
        assert!(
            !target
                .bind("COM_STMT_EXECUTE", Some(&params))
                .unwrap()
                .matches(&source, false),
            "duplicate branch cannot replace another value"
        );
        let wrong = cache
            .get(&format!(
                "SELECT id FROM kinds WHERE {}",
                branches.replacen("'default'", "'other'", 1)
            ))
            .bind("COM_QUERY", None)
            .unwrap();
        assert!(
            !target.metadata().unwrap().matches(&wrong, true),
            "fast path must check every fixed literal"
        );
    }
}

#[test]
fn heterogeneous_partial_or_metadata_keeps_ambiguity_bounded() {
    let mut cache = SqlCache::default();
    let source = cache
        .get(&format!(
            "SELECT id FROM kinds WHERE {}",
            (0..79)
                .map(|i| format!("(a={i} AND b={i})"))
                .collect::<Vec<_>>()
                .join(" OR ")
        ))
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get(&format!(
        "SELECT id FROM kinds WHERE {}",
        (0..79)
            .map(|i| format!("(a={i} AND b=?)"))
            .collect::<Vec<_>>()
            .join(" OR ")
    ));
    assert!(
        !target.metadata().unwrap().matches(&source, true),
        "heterogeneous partial templates keep the bounded assignment fallback"
    );
}
