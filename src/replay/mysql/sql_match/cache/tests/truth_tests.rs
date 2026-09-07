use super::*;

#[test]
fn truth_tests_compose_with_tuple_reordering_without_changing_boolean_semantics() {
    for truth in [
        "IS TRUE",
        "IS NOT TRUE",
        "IS FALSE",
        "IS NOT FALSE",
        "IS UNKNOWN",
        "IS NOT UNKNOWN",
    ] {
        let source = format!(
            "SELECT id FROM kinds WHERE kind='Team' AND (name,namespace,user_id) IN (('a','default',0),('b','default',1),('c','default',2),('d','default',3),('','default',4)) AND active {truth}"
        );
        let target = format!(
            "SELECT id FROM kinds WHERE active {truth} AND (name,namespace,user_id) IN (('','default',4),('d','default',3),('c','default',2),('b','default',1),('a','default',0)) AND kind='Team'"
        );
        assert!(equal(&source, &target), "{truth}");
        for changed in [
            "IS TRUE",
            "IS NOT TRUE",
            "IS FALSE",
            "IS NOT FALSE",
            "IS UNKNOWN",
            "IS NOT UNKNOWN",
            "IS NULL",
            "= 1",
            "= 0",
            "= NULL",
        ] {
            if changed != truth {
                assert!(
                    !equal(&source, &target.replace(truth, changed)),
                    "{truth} is not normalized to {changed}"
                );
            }
        }
        let mut cache = SqlCache::default();
        let bound = cache
            .get(&format!(
                "SELECT id FROM kinds WHERE active {truth} AND user_id=7"
            ))
            .bind("COM_QUERY", None)
            .unwrap();
        let prepared = cache.get(&format!(
            "SELECT id FROM kinds WHERE user_id=? AND active {truth}"
        ));
        assert!(prepared.metadata().unwrap().matches(&bound, true));
        for (value, expected) in [(7, true), (8, false)] {
            assert_eq!(
                prepared
                    .bind(
                        "COM_STMT_EXECUTE",
                        Some(&[mysql_json("integer", json!(value))])
                    )
                    .unwrap()
                    .matches(&bound, false),
                expected
            );
        }
    }
}

#[test]
fn truth_test_grammar_and_effectful_operands_remain_strict() {
    let mut cache = SqlCache::default();
    for expr in [
        "active IS 1",
        "active IS 0",
        "active IS ?",
        "active IS 'true'",
        "custom_function() IS TRUE",
        "@value IS NOT FALSE",
        "(SELECT active FROM other) IS UNKNOWN",
    ] {
        assert!(
            cache
                .get(&format!("SELECT id FROM kinds WHERE {expr}"))
                .metadata()
                .is_none(),
            "{expr}"
        );
    }
}
