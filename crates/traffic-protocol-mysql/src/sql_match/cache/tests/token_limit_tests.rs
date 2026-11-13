use super::*;

#[test]
fn large_sql_parses_without_cache_admission_and_keeps_literal_bytes_exact() {
    let text = "x".repeat(580_000);
    let sql = format!("SELECT id FROM tasks WHERE payload='{text}' AND id=7");
    let mut cache = SqlCache::default();
    let recorded = cache.get(&sql).bind("COM_QUERY", None).unwrap();
    assert!(cache.entries.is_empty());
    let params = [
        mysql_json("string", json!(text)),
        mysql_json("integer", json!(7)),
    ];
    let template = cache.get("SELECT id FROM tasks WHERE payload=? AND id=?");
    assert!(
        template
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );
    let mut changed = params.clone();
    changed[0] = mysql_json("string", json!("x".repeat(579_999)));
    assert!(
        !template
            .bind("COM_STMT_EXECUTE", Some(&changed))
            .unwrap()
            .matches(&recorded, false)
    );
    assert!(
        cache
            .get(&format!(
                "SELECT id FROM tasks WHERE payload='{}'",
                "x".repeat(8 * 1024 * 1024)
            ))
            .bind("COM_QUERY", None)
            .is_none()
    );
}

fn list(count: usize, reverse: bool) -> String {
    let mut values = (0..count).map(|v| v.to_string()).collect::<Vec<_>>();
    if reverse {
        values.reverse();
    }
    values.join(",")
}

#[test]
fn semantic_predicates_accept_32768_tokens_and_recheck_bound_values() {
    let source = format!("SELECT id FROM tasks WHERE id IN ({})", list(16_380, false));
    assert_eq!(tokens(&source).unwrap().len(), 32_768);
    let mut cache = SqlCache::default();
    let recorded = cache.get(&source).bind("COM_QUERY", None).unwrap();
    let sql = format!(
        "SELECT id FROM tasks WHERE id IN ({})",
        vec!["?"; 16_380].join(",")
    );
    let compiled = cache.get(&sql);
    let mut params = (0..16_380)
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
    params[0] = mysql_json("integer", json!(16_380));
    assert!(
        !compiled
            .bind("COM_STMT_EXECUTE", Some(&params))
            .unwrap()
            .matches(&recorded, false)
    );

    let oversized = format!("SELECT id FROM tasks WHERE id IN ({})", list(16_381, false));
    assert!(cache.get(&oversized).bind("COM_QUERY", None).is_none());
}

#[test]
fn full_query_list_matching_uses_the_same_32768_token_budget() {
    let sql = |count, reverse| {
        format!(
            "SELECT id FROM tasks WHERE id IN ({}) UNION ALL SELECT id FROM tasks WHERE id=9999",
            list(count, reverse)
        )
    };
    let source = sql(12_000, false);
    assert!(tokens(&source).unwrap().len() > 16_384);
    let mut cache = SqlCache::default();
    let compiled = cache.get(&source);
    assert!(compiled.query_in.is_some());
    let recorded = compiled.bind("COM_QUERY", None).unwrap();
    let target = cache
        .get(&sql(12_000, true))
        .bind("COM_QUERY", None)
        .unwrap();
    assert!(target.matches(&recorded, false));
    let changed = cache
        .get(&sql(11_999, true))
        .bind("COM_QUERY", None)
        .unwrap();
    assert!(!changed.matches(&recorded, false));

    let oversized = sql(16_380, false);
    assert!(tokens(&oversized).unwrap().len() > 32_768);
    assert!(cache.get(&oversized).bind("COM_QUERY", None).is_none());
}
