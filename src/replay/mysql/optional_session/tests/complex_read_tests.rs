use super::super::read::{Effect, classify};
use super::*;

const RANKED_READ: &str = "SELECT ranked.id FROM (
    SELECT combined.id, row_number() OVER (
        PARTITION BY combined.id ORDER BY combined.rank ASC, combined.id DESC
    ) AS row_num FROM (
        SELECT k.id, 0 AS rank FROM kinds k WHERE k.owner=7
        UNION ALL
        SELECT k.id, 1 AS rank FROM kinds k
        INNER JOIN members m ON m.resource_id=k.id AND m.kind IN ('Team','TEAM')
        WHERE m.member_id=7 AND k.active IS TRUE
        UNION ALL
        SELECT k.id, 2 AS rank FROM kinds k WHERE EXISTS (
            SELECT 1 FROM members m WHERE m.resource_id=k.id AND m.member_id=7
        ) AND k.namespace NOT IN ('private','internal')
    ) combined
) ranked WHERE ranked.row_num=1 ORDER BY ranked.id DESC LIMIT 0,100";

const COUNT_READ: &str = "SELECT count(distinct(combined_team_counts.team_id)) AS count_1
    FROM (SELECT kinds.id AS team_id FROM kinds WHERE kinds.user_id=7
    UNION SELECT kinds.id AS team_id FROM kinds WHERE kinds.namespace='shared') combined_team_counts";

#[test]
fn count_distinct_over_union_preserves_read_session_cleanup() {
    for sql in [
        COUNT_READ,
        "SELECT COUNT(*) FROM users",
        "SELECT COUNT(id) FROM users",
        "SELECT COUNT(1) FROM users",
        "SELECT COUNT(DISTINCT id) FROM users",
    ] {
        assert_eq!(classify(sql), Effect::ReadOnly, "{sql}");
    }
    let mut count = read(101, 1);
    count["sql"] = json!(COUNT_READ);
    count["response"]["server_status"] = json!(33);
    let mut rollback = cleanup(102);
    rollback["server_status_before"] = json!(33);
    let mut records = vec![read(100, 0), count, rollback, exchange(103, "ROLLBACK")];
    assert_eq!(optional(&records), [2, 3].into());
    for sql in [
        "SELECT COUNT(GET_LOCK('x',1)) FROM users",
        "SELECT COUNT((SELECT GET_LOCK('x',1))) FROM users",
        "SELECT COUNT(*) FROM (SELECT id FROM users FOR UPDATE) u",
    ] {
        assert_ne!(classify(sql), Effect::ReadOnly, "{sql}");
        records[1]["sql"] = json!(sql);
        assert_eq!(optional(&records), [3].into(), "{sql}");
    }
    records[1]["sql"] = json!(COUNT_READ);
    records[0]
        .as_object_mut()
        .unwrap()
        .remove("server_status_before");
    assert_eq!(optional(&records), [3].into());
}

#[test]
fn ranked_union_join_and_exists_check_exclusions_in_every_child() {
    assert_eq!(classify(RANKED_READ), Effect::ReadOnly);
    for sql in [
        "SELECT id FROM users UNION SELECT id FROM users",
        "SELECT t.id FROM (SELECT id FROM users ORDER BY id LIMIT 5) t",
        "SELECT u.id FROM users u LEFT JOIN members m ON u.id=m.id",
        "SELECT id FROM users WHERE NOT EXISTS (SELECT id FROM members WHERE id=7)",
    ] {
        assert_eq!(classify(sql), Effect::ReadOnly, "{sql}");
    }
    for (before, after) in [
        ("combined.id ORDER BY", "GET_LOCK('x',1) ORDER BY"),
        ("combined.rank ASC", "GET_LOCK('x',1) ASC"),
        ("row_number()", "GET_LOCK('x',1)"),
        ("row_number()", "row_number(GET_LOCK('x',1))"),
        ("0 AS rank", "GET_LOCK('x',1) AS rank"),
        ("m.resource_id=k.id", "m.resource_id=GET_LOCK('x',1)"),
        ("m.member_id=7", "m.member_id=GET_LOCK('x',1)"),
        (
            "SELECT 1 FROM members",
            "SELECT GET_LOCK('x',1) FROM members",
        ),
        ("k.owner=7", "k.owner=7 FOR UPDATE"),
        ("SELECT k.id, 0", "SELECT @x:=k.id, 0"),
        ("ranked.row_num=1", "GET_LOCK('x',1)=1"),
        ("ORDER BY ranked.id DESC", "ORDER BY GET_LOCK('x',1) DESC"),
        ("LIMIT 0,100", "LIMIT 0,GET_LOCK('x',1)"),
    ] {
        let sql = RANKED_READ.replace(before, after);
        assert_ne!(classify(&sql), Effect::ReadOnly, "{before} -> {after}");
    }
    for sql in [
        "SELECT id FROM (SELECT id FROM users FOR UPDATE) t",
        "SELECT id FROM users WHERE EXISTS (SELECT id FROM members FOR UPDATE)",
        "SELECT id FROM users JOIN (SELECT GET_LOCK('x',1) FROM members) m ON 1=1",
        "SELECT row_number() OVER (PARTITION BY id ORDER BY id ROWS GET_LOCK('x',1) PRECEDING) FROM users",
        "SELECT row_number() OVER w FROM users WINDOW w AS (ORDER BY GET_LOCK('x',1))",
        "SELECT id FROM users UNION SELECT id FROM users FOR UPDATE",
        "SELECT id FROM users; UPDATE users SET id=1",
    ] {
        assert_ne!(classify(sql), Effect::ReadOnly, "{sql}");
    }
}

#[test]
fn large_predicate_width_preserves_read_proof_and_checks_every_branch() {
    for size in [63, 64, 65, 79, 128, 256] {
        for op in [" OR ", " AND "] {
            let clauses = (0..size)
                .map(|i| format!("(user_id={i} AND name='' AND namespace='default')"))
                .collect::<Vec<_>>();
            let sql = format!("SELECT id FROM kinds WHERE {}", clauses.join(op));
            assert_eq!(classify(&sql), Effect::ReadOnly, "{size} {op}");
            for index in [0, size / 2, size - 1] {
                let mut clauses = clauses.clone();
                clauses[index] = "GET_LOCK('x',1)=1".to_owned();
                let sql = format!("SELECT id FROM kinds WHERE {}", clauses.join(op));
                assert_ne!(classify(&sql), Effect::ReadOnly, "{size} {index}");
            }
        }
    }
    let oversized = format!(
        "SELECT id FROM kinds WHERE {}",
        vec!["id=1"; 1500].join(" OR ")
    );
    assert_eq!(classify(&oversized), Effect::Unknown);
}

#[test]
fn interleaved_ranked_reads_and_large_or_preserve_cleanup_and_required_business_reads() {
    let mut ranked = read(101, 1);
    ranked["sql"] = json!(RANKED_READ);
    ranked["response"]["server_status"] = json!(33);
    let mut large = read(102, 33);
    large["sql"] = json!(format!(
        "SELECT id FROM kinds WHERE {}",
        (0..79)
            .map(|i| format!("(user_id={i} AND name='')"))
            .collect::<Vec<_>>()
            .join(" OR ")
    ));
    let short_id = Uuid::new_v4();
    let short = [read(900, 0), cleanup(901), exchange(902, "ROLLBACK")].map(|mut r| {
        r["connection_id"] = json!(short_id);
        r
    });
    let mut records = vec![
        read(100, 0),
        ranked,
        short[0].clone(),
        large,
        short[1].clone(),
        short[2].clone(),
        cleanup(103),
        exchange(104, "ROLLBACK"),
    ];
    assert_eq!(optional(&records), [4, 5, 6, 7].into());
    records[1]["sql"] = json!(RANKED_READ.replace("0 AS rank", "GET_LOCK('x',1) AS rank"));
    assert_eq!(optional(&records), [4, 5, 7].into());
}
