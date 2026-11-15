//! Native read-back preserves stored bytes while global fields validate their values.
use super::*;

#[test]
fn contextual_json_readback_preserves_the_matched_write_format_and_exact_stored_time() {
    let owner = native_runtime(json!({
        "id":"read-current", "match":{"operation":"SET","key":{"kind":"affix","prefix":"session:"}},
        "effect":{"kind":"identity","value_type":"string",
            "capture":{"kind":"redis_argument","index":1},"references":[],
            "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,"state_epochs":true}]},
        "proof":{"source":"session.rs:1","fact":"The Case reads its own successful SET and preserves its complete stored value"}
    }));
    let host = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let connection = uuid::Uuid::new_v4();
    let mut context = RedisRequestContext::without_exchange("case", &host, 0, "SET");
    context.recorded_at = DateTime::from_timestamp(1000, 0);
    context.actual_at = DateTime::from_timestamp(2000, 0);
    context.connection_id = Some(connection);
    context.sequence = Some(1);
    let source_json = r#"{"id": "11", "at": 1005.0, "stable": true}"#;
    let target_json = r#"{"stable":true,"at":2005.25,"id":"999"}"#;
    let source = args(&["session:1", source_json]);
    let target = args(&["session:1", target_json]);
    owner
        .commit(
            owner
                .preview_redis_context(&context, &source, &target)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let writes = owner
        .preview_redis_read_back_write(
            &context,
            &source,
            &target,
            b"+OK\r\n",
            DateTime::from_timestamp(1001, 0),
        )
        .unwrap();
    owner.commit_redis_read_back_write(writes).unwrap();
    owner
        .prepare_redis_time_write(
            &context,
            &source,
            &target,
            b"+OK\r\n",
            DateTime::from_timestamp(1001, 0),
        )
        .unwrap()
        .unwrap()
        .publish(DateTime::from_timestamp(2001, 0).unwrap())
        .unwrap();

    context.command = "GET";
    context.sequence = Some(2);
    context.recorded_at = DateTime::from_timestamp(1010, 0);
    context.actual_at = DateTime::from_timestamp(2020, 0);
    let keys = args(&["session:1"]);
    let original = bulk(source_json);
    let native = owner
        .prepare_redis_read_back(&context, &keys, &keys, &original)
        .unwrap()
        .unwrap();
    assert_eq!(native.response, bulk(target_json));
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
            &original,
            DateTime::from_timestamp(1011, 0),
            context.actual_at,
            context.recorded_at,
            connection,
            2,
        )
        .unwrap()
        .unwrap();
    let now = DateTime::from_timestamp(2021, 0).unwrap();
    let rendered = delivery.render(now).unwrap();
    assert_eq!(
        crate::json_value::parse(&redis_bulk_payload(&rendered).unwrap().unwrap()),
        crate::json_value::parse(target_json.as_bytes()),
        "stored Target time and identity must already survive global delivery"
    );
    assert_eq!(
        delivery
            .render_consistent(now, Some(&native.response))
            .unwrap(),
        native.response
    );
    for changed in [
        r#"{"stable":false,"at":2005.25,"id":"999"}"#,
        r#"{"stable":true,"at":2005.25,"id":"888"}"#,
        r#"{"stable":true,"at":2005.5,"id":"999"}"#,
        r#"{"stable":true,"at":2005.25,"id":"999","extra":true}"#,
    ] {
        assert!(
            delivery
                .render_consistent(now, Some(&bulk(changed)))
                .is_err()
        );
    }
}

#[test]
fn contextual_json_consistency_keeps_response_structure_and_unselected_bytes_exact() {
    let owner = identity_runtime();
    bind(&owner);
    let original = array(&[
        bulk("field"),
        bulk(r#"{"id": "11", "stable": true}"#),
        bulk("other"),
        bulk("opaque"),
    ]);
    let prepared = delivery(&owner, "HGETALL", &["hash:1"], &original);
    let copied = r#"{"stable":true,"id":"999"}"#;
    let native = array(&[bulk("field"), bulk(copied), bulk("other"), bulk("opaque")]);
    let now = DateTime::from_timestamp(2000, 0).unwrap();
    assert_eq!(
        prepared.render_consistent(now, Some(&native)).unwrap(),
        native
    );
    for bad in [
        array(&[
            bulk("different-field"),
            bulk(copied),
            bulk("other"),
            bulk("opaque"),
        ]),
        array(&[bulk("field"), bulk(copied), bulk("other"), bulk("changed")]),
        array(&[
            bulk("field"),
            b"$-1\r\n".to_vec(),
            bulk("other"),
            bulk("opaque"),
        ]),
        array(&[
            bulk("field"),
            bulk("not-json"),
            bulk("other"),
            bulk("opaque"),
        ]),
        [native.as_slice(), b"+EXTRA\r\n"].concat(),
    ] {
        assert!(prepared.render_consistent(now, Some(&bad)).is_err());
    }
}
