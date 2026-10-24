use super::*;

fn prepare(
    runtime: &RequestContracts,
    command: &str,
    keys: &[&str],
    source: &[u8],
    completed: Option<DateTime<Utc>>,
) -> PreparedRedisTimeRead {
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut context = RedisRequestContext::without_exchange("case", &target, 0, command);
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    runtime
        .prepare_redis_time_read(&context, &args(keys), &args(keys), source, completed)
        .unwrap()
        .unwrap()
}

#[test]
fn copied_time_requires_the_real_read_to_precede_the_write_on_both_sides() {
    let source = r#"{"at":100,"stable":"checked"}"#;
    let target = r#"{"at":555,"stable":"checked"}"#;
    for (source_completed, target_completed, passed) in [
        (None, 2000, false),
        (DateTime::from_timestamp(1001, 0), 2000, false),
        (DateTime::from_timestamp(1000, 0), 2001, false),
        (DateTime::from_timestamp(1000, 0), 2000, true),
    ] {
        let runtime = runtime();
        let pending = prepare(&runtime, "GET", &["key"], &bulk(source), source_completed);
        assert!(preview(&runtime, "SET", &["key", source], &["key", target]).is_err());
        pending
            .publish(
                &bulk(target),
                DateTime::from_timestamp(target_completed, 0).unwrap(),
            )
            .unwrap();
        assert_eq!(
            preview(&runtime, "SET", &["key", source], &["key", target]).is_ok(),
            passed
        );
    }
}

#[test]
fn a_copied_time_cannot_move_to_another_key_hash_field_or_unobserved_value() {
    let runtime = runtime();
    let source = r#"{"at":100,"stable":"checked"}"#;
    let target = r#"{"at":555,"stable":"checked"}"#;
    prepare(
        &runtime,
        "HGET",
        &["hash", "first"],
        &bulk(source),
        DateTime::from_timestamp(1000, 0),
    )
    .publish(&bulk(target), DateTime::from_timestamp(2000, 0).unwrap())
    .unwrap();
    assert!(
        preview(
            &runtime,
            "HSET",
            &["hash", "first", source],
            &["hash", "first", target]
        )
        .is_ok()
    );
    for (key, field, value) in [
        ("hash", "second", target),
        ("other", "first", target),
        ("hash", "first", r#"{"at":556,"stable":"checked"}"#),
        ("hash", "first", r#"{"at":555,"stable":"wrong"}"#),
    ] {
        assert!(
            preview(
                &runtime,
                "HSET",
                &[key, field, source],
                &[key, field, value]
            )
            .is_err(),
            "{key}/{field}"
        );
    }
}

#[test]
fn equal_historical_times_pass_exactly_without_borrowing_a_copy_permission() {
    let runtime = runtime();
    let same = r#"{"at":100,"stable":true}"#;
    assert!(preview(&runtime, "SET", &["key", same], &["key", same]).is_ok());
    assert!(!runtime.has_time_copies("case"));
    assert!(
        preview(
            &runtime,
            "SET",
            &["key", same],
            &["key", r#"{"at":555,"stable":true}"#]
        )
        .is_err()
    );
}

#[test]
fn successful_json_writes_preserve_stored_times_on_later_reads_without_authored_rules() {
    let owner = runtime();
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut write = RedisRequestContext::without_exchange("case", &host, 0, "RPUSH");
    write.recorded_at = DateTime::from_timestamp(1000, 0);
    write.actual_at = DateTime::from_timestamp(2000, 0);
    let a = r#"{"at":1005,"stable":true}"#;
    let b = r#"{"at":2005,"stable":true}"#;
    let source = args(&["list", a]);
    let target = args(&["list", b]);
    let accepted = owner
        .preview_redis_context(&write, &source, &target)
        .unwrap()
        .unwrap();
    let pending = owner
        .prepare_redis_time_write(
            &write,
            &source,
            &target,
            b":1\r\n",
            DateTime::from_timestamp(1001, 0),
        )
        .unwrap()
        .unwrap();
    assert!(!owner.has_time_copies("case"));
    owner.commit(accepted).unwrap();
    pending
        .publish(DateTime::from_timestamp(2001, 0).unwrap())
        .unwrap();
    let keys = args(&["list", "0", "-1"]);
    let raw = array(&[bulk(a)]);
    let delivery = owner
        .prepare_redis_delivery(
            "case",
            "case",
            &host,
            0,
            None,
            "LRANGE",
            &keys,
            &keys,
            &raw,
            DateTime::from_timestamp(1101, 0),
            DateTime::from_timestamp(2300, 0),
            DateTime::from_timestamp(1100, 0),
            uuid::Uuid::new_v4(),
            2,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        delivery
            .render(DateTime::from_timestamp(2301, 0).unwrap())
            .unwrap(),
        array(&[bulk(b)])
    );
    assert!(
        owner
            .prepare_redis_time_write(
                &write,
                &source,
                &target,
                b"-ERR no write\r\n",
                DateTime::from_timestamp(1001, 0)
            )
            .unwrap()
            .is_none()
    );
    assert!(
        owner
            .prepare_redis_delivery(
                "case",
                "case",
                &host,
                0,
                None,
                "LRANGE",
                &keys,
                &keys,
                &raw,
                DateTime::from_timestamp(1101, 0),
                DateTime::from_timestamp(1900, 0),
                DateTime::from_timestamp(1100, 0),
                uuid::Uuid::new_v4(),
                2
            )
            .unwrap()
            .is_err()
    );
}

#[test]
fn conflicting_stored_time_targets_do_not_guess_which_write_a_read_observed() {
    let owner = runtime();
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let mut write = RedisRequestContext::without_exchange("case", &host, 0, "SET");
    write.recorded_at = DateTime::from_timestamp(1000, 0);
    write.actual_at = DateTime::from_timestamp(2000, 0);
    let a = r#"{"at":1005}"#;
    for b in [r#"{"at":2005}"#, r#"{"at":2006}"#] {
        owner
            .prepare_redis_time_write(
                &write,
                &args(&["key", a]),
                &args(&["key", b]),
                b"+OK\r\n",
                DateTime::from_timestamp(1001, 0),
            )
            .unwrap()
            .unwrap()
            .publish(DateTime::from_timestamp(2001, 0).unwrap())
            .unwrap();
    }
    let keys = args(&["key"]);
    assert!(
        owner
            .prepare_redis_delivery(
                "case",
                "case",
                &host,
                0,
                None,
                "GET",
                &keys,
                &keys,
                &bulk(a),
                DateTime::from_timestamp(1101, 0),
                DateTime::from_timestamp(2300, 0),
                DateTime::from_timestamp(1100, 0),
                uuid::Uuid::new_v4(),
                3
            )
            .unwrap()
            .is_err()
    );
}
