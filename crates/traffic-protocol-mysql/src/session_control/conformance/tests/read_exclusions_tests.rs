use super::super::read::{Effect, classify};
use super::*;

#[test]
fn ordinary_select_shapes_do_not_require_registration_for_cleanup() {
    for sql in [
        "SELECT id FROM kinds WHERE COALESCE(JSON_UNQUOTE(JSON_EXTRACT(json, '$.spec.directAccessRequirement')), '') IN ('', 'read')",
        "SELECT CASE WHEN JSON_EXTRACT(json, '$.status') IS NULL THEN 0 ELSE 1 END FROM kinds",
        "SELECT id FROM kinds WHERE id IN (SELECT resource_id FROM members WHERE status='approved')",
        "SELECT (SELECT MAX(id) FROM members) FROM kinds",
        "WITH readable AS (SELECT id FROM kinds WHERE active=1) SELECT id FROM readable",
        "SELECT SUM(id), AVG(id), GROUP_CONCAT(name ORDER BY id) FROM kinds GROUP BY namespace HAVING COUNT(*)>1",
        "SELECT ROW_NUMBER() OVER w FROM kinds WINDOW w AS (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)",
        "SELECT COALESCE(CAST(id AS CHAR), name) FROM kinds WHERE name REGEXP '^a'",
        "SELECT INSERT(name, 1, 1, 'x'), REPLACE(name, 'a', 'b') FROM kinds",
        "SELECT id FROM kinds WHERE (id,name) IN ((1,LOWER('A')), (2,UPPER('b')))",
        "SELECT 1",
        "SELECT app.report_function(id), custom_function() FROM kinds",
        "SELECT COUNT(DISTINCT id,name) FROM kinds",
        "SELECT LAST_INSERT_ID()",
    ] {
        assert_eq!(classify(sql), Effect::ReadOnly, "{sql}");
        let mut query = read(101, 1);
        query["sql"] = json!(sql);
        let records = [read(100, 0), query, cleanup(102), exchange(103, "ROLLBACK")];
        assert_eq!(optional(&records), [2, 3].into(), "{sql}");
    }
}

#[test]
fn common_side_effects_are_excluded_at_any_query_depth() {
    for sql in [
        "SELECT id FROM kinds FOR UPDATE",
        "SELECT id FROM kinds FOR SHARE",
        "SELECT id FROM kinds LOCK IN SHARE MODE",
        "SELECT id FROM kinds FOR UPDATE SKIP LOCKED",
        "SELECT id FROM kinds WHERE id IN (SELECT id FROM members FOR UPDATE)",
        "SELECT (SELECT id FROM members FOR SHARE) FROM kinds",
        "WITH locked AS (SELECT id FROM kinds FOR UPDATE) SELECT * FROM locked",
        "SELECT id FROM (SELECT id FROM kinds LOCK IN SHARE MODE) k",
        "SELECT id INTO OUTFILE '/tmp/side-effect' FROM kinds",
        "SELECT id FROM kinds INTO DUMPFILE '/tmp/side-effect'",
        "SELECT id INTO @last_id FROM kinds",
        "SELECT @x:=id FROM kinds",
        "SELECT @@session.autocommit",
        "SELECT SQL_CALC_FOUND_ROWS id FROM kinds",
        "SELECT COALESCE(GET_LOCK('x',1), 0) FROM kinds",
        "SELECT id FROM kinds WHERE EXISTS (SELECT RELEASE_LOCK('x'))",
        "SELECT CASE WHEN id=1 THEN RELEASE_ALL_LOCKS() ELSE 0 END FROM kinds",
        "SELECT COUNT(app.GET_LOCK('x',1)) FROM kinds",
        "SELECT `get_lock`('x',1) FROM kinds",
        "SELECT LAST_INSERT_ID(7)",
        "SELECT SLEEP(1)",
        "SELECT BENCHMARK(1000,MD5('x'))",
        "SELECT LOAD_FILE('/tmp/private')",
        "SELECT service_get_write_locks('ns','name',1)",
        "SELECT sys_exec('command')",
        "SELECT id FROM kinds; DELETE FROM kinds",
    ] {
        assert_ne!(classify(sql), Effect::ReadOnly, "{sql}");
        let mut query = read(101, 1);
        query["sql"] = json!(sql);
        assert_eq!(
            optional(&[
                read(100, 0),
                query,
                read(102, 1),
                cleanup(103),
                exchange(104, "ROLLBACK")
            ]),
            [4].into(),
            "a later ordinary read must not hide the excluded query: {sql}"
        );
    }
}

#[test]
fn strings_comments_and_quoted_columns_do_not_trigger_exclusions() {
    for sql in [
        "SELECT 'FOR UPDATE', 'INTO OUTFILE', 'GET_LOCK(', '@x:=' FROM kinds",
        "SELECT JSON_EXTRACT(json, '$.for update') FROM kinds",
        "SELECT id /* FOR UPDATE GET_LOCK('x',1) */ FROM kinds",
        "SELECT id FROM kinds -- LOCK IN SHARE MODE\nWHERE active=1",
        "SELECT `into`, `update`, `get_lock`, `@x` FROM kinds",
        "SELECT `SQL_CALC_FOUND_ROWS`, `PROCEDURE`, `call` FROM kinds",
    ] {
        assert_eq!(classify(sql), Effect::ReadOnly, "{sql}");
    }
    for sql in [
        "SELECT /*!50000 GET_LOCK('x',1) */ id FROM kinds",
        "SELECT /*+ HINT */ id FROM kinds",
        "SELECT id FROM kinds WHERE id=",
    ] {
        assert_eq!(classify(sql), Effect::Unknown, "{sql}");
    }
}
