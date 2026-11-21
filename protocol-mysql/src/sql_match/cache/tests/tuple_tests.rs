use super::*;

#[test]
fn tuples_are_atomic_multiset_values_with_positional_types_nulls_and_duplicates() {
    for (a, b) in [
        ("(id,uid) IN ((1,2),(3,4))", "(id,uid) IN ((3,4),(1,2))"),
        (
            "(id,name) IN ((1,'a'),(2,'b'),(1,'a'))",
            "(id,name) IN ((1,'a'),(1,'a'),(2,'b'))",
        ),
        (
            "(id,name) NOT IN ((1,NULL),(NULL,'b'),(2,'c'))",
            "(id,name) NOT IN ((2,'c'),(1,NULL),(NULL,'b'))",
        ),
        (
            "(id,name,uid) IN ((18446744073709551615,'O\\'Brien',-1),(2,X'00ff',3))",
            "(id,name,uid) IN ((2,X'00ff',3),(18446744073709551615,'O''Brien',-1))",
        ),
        (
            "tenant=7 AND (namespace,name) IN (('default','a'),('shared','b'))",
            "(namespace,name) IN (('shared','b'),('default','a')) AND tenant=7",
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
    let source = "SELECT id FROM tasks WHERE (id,name) IN ((1,'a'),(2,'b'),(1,'a'))";
    for changed in [
        "(id,name) IN ((1,'b'),(2,'a'),(1,'a'))", // columns match individually; row pairing does not
        "(id,name) IN ((1,'a'),(2,'b'))",         // missing duplicate
        "(id,name) IN ((1,'a'),(2,'b'),(2,'b'))", // changed multiplicity
        "(name,id) IN (('a',1),('b',2),('a',1))", // field order remains strict
        "(id,name) IN (('1','a'),('2','b'),('1','a'))", // changed type
        "(id,name) IN ((1,'A'),(2,'b'),(1,'a'))", // changed bytes
        "(id,name) NOT IN ((1,'a'),(2,'b'),(1,'a'))",
    ] {
        assert!(
            !equal(source, &format!("SELECT id FROM tasks WHERE {changed}")),
            "{changed}"
        );
    }
}

#[test]
fn tuple_shape_and_unproven_expressions_stay_strict() {
    let mut cache = SqlCache::default();
    for predicate in [
        "(id,uid) IN ((1,2),(3,4,5))",
        "(id,uid) IN (1,2)",
        "id IN ((1,2),(3,4))",
        "(id,uid) IN ((1,2),NULL)",
        "(id,uid) IN ((1,2),(3,'4'))", // mixed types in one component
        "(id,uid) IN ((1,2),(3,uid))",
        "(id,uid) IN ((1,2),(3,RAND()))",
        "(id+1,uid) IN ((1,2),(3,4))",
        "(id,uid) IN (SELECT id,uid FROM other)",
        "((id,uid),name) IN (((1,2),'a'),((3,4),'b'))",
        "(id,uid)=(1,2)",
        "(id,uid) IN ()",
    ] {
        let sql = format!("SELECT id FROM tasks WHERE {predicate}");
        assert!(cache.get(&sql).bind("COM_QUERY", None).is_none(), "{sql}");
    }
}

#[test]
fn tuple_prepare_keeps_partial_row_pairing_and_execute_rebinds_cached_slots() {
    let mut cache = SqlCache::default();
    let source = cache
        .get("SELECT id FROM tasks WHERE tenant=7 AND (id,uid) IN ((1,2),(3,2),(9,NULL))")
        .bind("COM_QUERY", None)
        .unwrap();
    let target =
        cache.get("SELECT id FROM tasks WHERE (id,uid) IN ((?,2),(1,?),(9,NULL)) AND tenant=?");
    assert!(
        target.metadata().unwrap().matches(&source, true),
        "a greedy partial-row assignment would fail"
    );
    for (values, expected) in [([3, 2, 7], true), ([2, 3, 7], false), ([3, 2, 8], false)] {
        let params = values.map(|value| mysql_json("integer", json!(value)));
        assert_eq!(
            target
                .bind("COM_STMT_EXECUTE", Some(&params))
                .unwrap()
                .matches(&source, false),
            expected
        );
    }
    let mismatch =
        cache.get("SELECT id FROM tasks WHERE (id,uid) IN ((?,3),(1,?),(9,NULL)) AND tenant=?");
    assert!(!mismatch.metadata().unwrap().matches(&source, true));
    let repeated =
        cache.get("SELECT id FROM tasks WHERE (id,uid) IN ((1,?),(1,?),(9,NULL)) AND tenant=?");
    assert!(
        !repeated.metadata().unwrap().matches(&source, true),
        "one source row cannot satisfy two partial rows"
    );
    let mixed = cache.get("SELECT id FROM tasks WHERE (id,name) IN ((?,?),(?,?))");
    let params = [
        mysql_json("integer", json!(1)),
        mysql_json("string", json!("a")),
        mysql_json("string", json!("2")),
        mysql_json("string", json!("b")),
    ];
    assert!(mixed.metadata().is_some());
    assert!(
        mixed.bind("COM_STMT_EXECUTE", Some(&params)).is_none(),
        "unknown types are validated on every execution"
    );
    assert_eq!(cache.compilations, 5);
}

#[test]
fn large_tuple_lists_reuse_compilation_and_bound_partial_prepare_work() {
    let mut cache = SqlCache::default();
    let rows = (0..200)
        .map(|i| format!("({i},'n{i}')"))
        .collect::<Vec<_>>()
        .join(",");
    let source = cache
        .get(&format!("SELECT id FROM tasks WHERE (id,name) IN ({rows})"))
        .bind("COM_QUERY", None)
        .unwrap();
    let target = cache.get(&format!(
        "SELECT id FROM tasks WHERE (id,name) IN ({})",
        vec!["(?,?)"; 200].join(",")
    ));
    assert!(target.metadata().unwrap().matches(&source, true));
    let mut params = (0..200)
        .rev()
        .flat_map(|i| {
            [
                mysql_json("integer", json!(i)),
                mysql_json("string", json!(format!("n{i}"))),
            ]
        })
        .collect::<Vec<_>>();
    assert!(
        target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false)
    );
    params[1] = mysql_json("string", json!("wrong pairing"));
    assert!(
        !target
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&source, false)
    );
    assert_eq!(cache.compilations, 2);
    let partial = cache.get(&format!(
        "SELECT id FROM tasks WHERE (id,name) IN ({})",
        vec!["(1,?)"; 200].join(",")
    ));
    assert!(
        !partial.metadata().unwrap().matches(&source, true),
        "ambiguous matching work is bounded"
    );
}
