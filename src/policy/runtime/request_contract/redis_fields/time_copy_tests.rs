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
fn redis_automatic_stored_times_keep_the_write_counterpart_across_repeated_reads() {
    for identities in [false, true] {
        let mut owner = runtime();
        if identities {
            let compiled = crate::policy::parse_and_compile_policy(
                "format: traffic-policy/v3\njson:\n  fields:\n    /unused_id: {kind: identity, formats: [string]}\n",
            )
            .unwrap();
            owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
        }
        let host = TargetKey {
            host: "cache.test".into(),
            port: 6379,
        };
        let a = r#"{"last_heartbeat":"1970-01-01T00:16:45Z","stable":true}"#;
        let b = r#"{"last_heartbeat":"1970-01-01T00:33:25Z","stable":true}"#;
        let mut write = RedisRequestContext::without_exchange("case", &host, 0, "SET");
        write.recorded_at = DateTime::from_timestamp(1000, 0);
        write.actual_at = DateTime::from_timestamp(2000, 0);
        let accepted = owner
            .preview_redis_context(&write, &args(&["device", a]), &args(&["device", b]))
            .unwrap()
            .unwrap();
        owner.commit(accepted).unwrap();
        owner
            .prepare_redis_time_write(
                &write,
                &args(&["device", a]),
                &args(&["device", b]),
                b"+OK\r\n",
                DateTime::from_timestamp(1001, 0),
            )
            .unwrap()
            .unwrap()
            .publish(DateTime::from_timestamp(2001, 0).unwrap())
            .unwrap();
        let keys = args(&["device"]);
        let raw = bulk(a);
        for (sequence, source_started, target_started) in [(2, 1100, 2300), (3, 1110, 2310)] {
            let mut read = RedisRequestContext::without_exchange("case", &host, 0, "GET");
            read.recorded_at = DateTime::from_timestamp(source_started, 0);
            read.actual_at = DateTime::from_timestamp(target_started, 0);
            let source_completed = DateTime::from_timestamp(source_started + 1, 0);
            let pending = owner
                .prepare_redis_time_read(&read, &keys, &keys, &raw, source_completed)
                .unwrap()
                .unwrap();
            let delivery = owner
                .prepare_redis_delivery(
                    "case",
                    "case",
                    &host,
                    0,
                    None,
                    "GET",
                    &keys,
                    &keys,
                    &raw,
                    source_completed,
                    read.actual_at,
                    read.recorded_at,
                    uuid::Uuid::new_v4(),
                    sequence,
                )
                .unwrap()
                .unwrap();
            let now = DateTime::from_timestamp(target_started + 1, 0).unwrap();
            let response = delivery.render(now).unwrap();
            assert_eq!(
                response,
                bulk(b),
                "read {sequence}, identities={identities}"
            );
            pending.publish(&response, now).unwrap();
        }
    }
}

#[test]
fn overlapping_source_gets_copy_only_the_same_value_after_real_target_delivery() {
    let owner = runtime();
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let source = r#"{"at":1005,"stable":true}"#;
    let delivered = r#"{"at":2005,"stable":true}"#;
    prepare(
        &owner,
        "GET",
        &["key"],
        &bulk(source),
        DateTime::from_timestamp(1002, 0),
    )
    .publish(&bulk(delivered), DateTime::from_timestamp(2002, 0).unwrap())
    .unwrap();

    let keys = args(&["key"]);
    let read = |payload, source_completed, target_started| {
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
                &bulk(payload),
                DateTime::from_timestamp(source_completed, 0),
                DateTime::from_timestamp(target_started, 0),
                DateTime::from_timestamp(1001, 0),
                uuid::Uuid::new_v4(),
                2,
            )
            .unwrap()
    };
    let response = read(source, 1003, 2300)
        .unwrap()
        .render(DateTime::from_timestamp(2301, 0).unwrap())
        .unwrap();
    assert_eq!(response, bulk(delivered));
    assert!(read(r#"{"at":1005,"stable":false}"#, 1003, 2300).is_err());
    assert!(read(source, 1001, 2300).is_err());
    assert!(read(source, 1003, 2001).is_err());
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

#[test]
fn redis_set_supersedes_a_replayed_read_that_arrived_before_the_write() {
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let source = r#"{"at":1003,"stable":true}"#;
    let stored = r#"{"at":2008,"stable":true}"#;
    for (first_read, source_write_completed, expected) in [
        (source, 999, Some(bulk(stored))),
        (r#"{"at":1003,"stable":false}"#, 999, None),
        (source, 1001, None),
    ] {
        let owner = runtime();
        prepare(
            &owner,
            "GET",
            &["key"],
            &bulk(first_read),
            DateTime::from_timestamp(1002, 0),
        )
        .publish(
            &bulk(&first_read.replace("1003", "2003")),
            DateTime::from_timestamp(2002, 0).unwrap(),
        )
        .unwrap();

        let mut write = RedisRequestContext::without_exchange("case", &host, 0, "SET");
        write.recorded_at = DateTime::from_timestamp(998, 0);
        write.actual_at = DateTime::from_timestamp(2003, 0);
        owner
            .prepare_redis_time_write(
                &write,
                &args(&["key", source]),
                &args(&["key", stored]),
                b"+OK\r\n",
                DateTime::from_timestamp(source_write_completed, 0),
            )
            .unwrap()
            .unwrap()
            .publish(DateTime::from_timestamp(2004, 0).unwrap())
            .unwrap();

        let keys = args(&["key"]);
        let actual = owner
            .prepare_redis_delivery(
                "case",
                "case",
                &host,
                0,
                None,
                "GET",
                &keys,
                &keys,
                &bulk(source),
                DateTime::from_timestamp(1101, 0),
                DateTime::from_timestamp(2300, 0),
                DateTime::from_timestamp(1100, 0),
                uuid::Uuid::new_v4(),
                3,
            )
            .unwrap()
            .and_then(|response| response.render(DateTime::from_timestamp(2301, 0).unwrap()));
        assert_eq!(
            actual.ok(),
            expected,
            "{first_read} at {source_write_completed}"
        );
    }
}

#[test]
fn redis_set_supersedes_a_get_that_started_early_but_replied_after_the_write() {
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let time = |seconds| DateTime::from_timestamp(seconds, 0).unwrap();
    let source = r#"{"last_heartbeat":"1970-01-01T00:16:40Z"}"#;
    let stored = r#"{"last_heartbeat":"1970-01-01T00:33:23Z"}"#;
    let keys = args(&["key"]);
    let response = bulk(source);
    for (source_read_started, separate_connection, set_publishes_first, later_conflicting_get) in [
        (1002, false, false, false),
        (1002, false, true, false),
        (1002, false, false, true),
        (999, true, false, false),
        (999, true, true, false),
        (999, false, false, false),
        (997, true, false, false),
    ] {
        let owner = runtime();
        let mut write = RedisRequestContext::without_exchange("case", &host, 0, "SET");
        write.connection_id = Some(uuid::Uuid::from_u128(1));
        write.recorded_at = Some(time(998));
        write.actual_at = Some(time(2001));
        let write = owner
            .prepare_redis_time_write(
                &write,
                &args(&["key", source, "EX", "60"]),
                &args(&["key", stored, "EX", "60"]),
                b"+OK\r\n",
                Some(time(1000)),
            )
            .unwrap()
            .unwrap();
        let mut read = RedisRequestContext::without_exchange("case", &host, 0, "GET");
        read.connection_id = Some(uuid::Uuid::from_u128(if separate_connection {
            2
        } else {
            1
        }));
        read.recorded_at = Some(time(source_read_started));
        read.actual_at = Some(time(2002));
        let early = owner
            .prepare_redis_time_read(&read, &keys, &keys, &response, Some(time(1003)))
            .unwrap()
            .unwrap();
        if set_publishes_first {
            write.publish(time(2004)).unwrap();
        }
        early.publish(&response, time(2006)).unwrap();
        if later_conflicting_get {
            read.recorded_at = Some(time(1004));
            read.actual_at = Some(time(2005));
            owner
                .prepare_redis_time_read(&read, &keys, &keys, &response, Some(time(1005)))
                .unwrap()
                .unwrap()
                .publish(&response, time(2007))
                .unwrap();
        }
        if !set_publishes_first {
            write.publish(time(2004)).unwrap();
        }
        let later = |source_started| {
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
                    &response,
                    Some(time(1011)),
                    Some(time(2010)),
                    Some(time(source_started)),
                    uuid::Uuid::new_v4(),
                    5,
                )
                .unwrap()
        };
        if later_conflicting_get
            || source_read_started < 998
            || source_read_started < 1000 && !separate_connection
        {
            assert!(later(1010).is_err());
        } else {
            assert_eq!(
                later(1010).unwrap().render(time(2011)).unwrap(),
                bulk(stored)
            );
            if source_read_started == 999 {
                assert_eq!(
                    later(999).unwrap().render(time(2011)).unwrap(),
                    bulk(stored)
                );
            }
        }
    }
}
