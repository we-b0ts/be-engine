use super::*;

fn list(count: usize, reverse: bool) -> String {
    let mut values = (0..count).map(|v| v.to_string()).collect::<Vec<_>>();
    if reverse {
        values.reverse();
    }
    values.join(",")
}

#[test]
fn semantic_predicates_accept_8192_tokens_and_recheck_bound_values() {
    let source = format!("SELECT id FROM tasks WHERE id IN ({})", list(4092, false));
    assert_eq!(tokens(&source).unwrap().len(), 8192);
    let mut cache = SqlCache::default();
    let recorded = cache.get(&source).bind("COM_QUERY", None).unwrap();
    let sql = format!(
        "SELECT id FROM tasks WHERE id IN ({})",
        vec!["?"; 4092].join(",")
    );
    let compiled = cache.get(&sql);
    let mut params = (0..4092)
        .rev()
        .map(|v| mysql_json("integer", json!(v)))
        .collect::<Vec<_>>();
    assert!(
        compiled
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
    assert!(compiled.metadata().unwrap().matches(&recorded, true));
    params[0] = mysql_json("integer", json!(4092));
    assert!(
        !compiled
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );

    let oversized = format!("SELECT id FROM tasks WHERE id IN ({})", list(4093, false));
    assert!(cache.get(&oversized).bind("COM_QUERY", None).is_none());
}

#[test]
fn full_query_list_matching_uses_the_same_8192_token_budget() {
    let sql = |count, reverse| {
        format!(
            "SELECT id FROM tasks WHERE id IN ({}) UNION ALL SELECT id FROM tasks WHERE id=9999",
            list(count, reverse)
        )
    };
    let source = sql(3000, false);
    assert!(tokens(&source).unwrap().len() > 4096);
    let mut cache = SqlCache::default();
    let compiled = cache.get(&source);
    assert!(compiled.query_in.is_some());
    let recorded = compiled.bind("COM_QUERY", None).unwrap();
    let target = cache.get(&sql(3000, true)).bind("COM_QUERY", None).unwrap();
    assert!(target.matches(&recorded, false));
    let changed = cache.get(&sql(2999, true)).bind("COM_QUERY", None).unwrap();
    assert!(!changed.matches(&recorded, false));

    let oversized = sql(4092, false);
    assert!(tokens(&oversized).unwrap().len() > 8192);
    assert!(cache.get(&oversized).bind("COM_QUERY", None).is_none());
}
