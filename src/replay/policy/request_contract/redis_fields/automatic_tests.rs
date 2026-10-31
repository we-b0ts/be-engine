use super::*;

const SOURCE: &str = "1970-01-01T00:16:50.000Z";
const TARGET: &str = "1970-01-01T00:33:30.000Z";

fn automatic_runtime() -> RequestContracts {
    let mut owner = runtime();
    owner
        .configure_compiled(Some(Arc::new(
            crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap(),
        )))
        .unwrap();
    owner
}

#[test]
fn native_time_values_match_without_keys_or_json_field_rules() {
    let owner = automatic_runtime();
    for (command, source, target) in [
        ("SET", vec!["physical", SOURCE], vec!["physical", TARGET]),
        (
            "HSET",
            vec!["physical", "field", SOURCE],
            vec!["physical", "field", TARGET],
        ),
        ("RPUSH", vec!["physical", SOURCE], vec!["physical", TARGET]),
        (
            "EVALSHA",
            vec!["script", "1", "physical", SOURCE, "42"],
            vec!["script", "1", "physical", TARGET, "42"],
        ),
    ] {
        let decision = preview(&owner, command, &source, &target).unwrap();
        assert!(
            decision
                .ids
                .iter()
                .any(|id| id == crate::value_contract::time::automatic::RULE_ID)
        );
        assert!(
            !decision
                .ids
                .iter()
                .any(|id| id == crate::policy::GLOBAL_JSON_ID)
        );
    }
    for (source, target) in [
        (vec!["physical", SOURCE], vec!["other-key", TARGET]),
        (
            vec!["physical", SOURCE, "EX", "30"],
            vec!["physical", TARGET, "EX", "31"],
        ),
        (vec!["physical", "1010"], vec!["physical", "2010"]),
        (
            vec!["physical", SOURCE],
            vec!["physical", "1970-01-01T00:33:30.0000Z"],
        ),
        (
            vec!["physical", SOURCE],
            vec!["physical", "1970-01-01T00:33:40.000Z"],
        ),
    ] {
        assert!(preview(&owner, "SET", &source, &target).is_err());
    }
    for target in [
        vec!["other-script", "1", "physical", TARGET, "42"],
        vec!["script", "1", "other-key", TARGET, "42"],
        vec!["script", "1", "physical", TARGET, "43"],
    ] {
        assert!(
            preview(
                &owner,
                "EVALSHA",
                &["script", "1", "physical", SOURCE, "42"],
                &target
            )
            .is_err()
        );
    }
}

#[test]
fn automatic_scalar_delivery_and_copies_keep_raw_resp_payloads() {
    let owner = automatic_runtime();
    let target = TargetKey {
        host: "cache.test".into(),
        port: 6379,
    };
    let keys = args(&["physical"]);
    let source = bulk(SOURCE);
    let delivery = owner
        .prepare_redis_delivery(
            "case",
            "case",
            &target,
            0,
            None,
            "GET",
            &keys,
            &keys,
            &source,
            DateTime::from_timestamp(1000, 0),
            DateTime::from_timestamp(2000, 0),
            DateTime::from_timestamp(1000, 0),
            uuid::Uuid::new_v4(),
            1,
        )
        .unwrap()
        .unwrap();
    let rendered = delivery
        .render(DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    assert_eq!(rendered, bulk(SOURCE));
    assert_eq!(source, bulk(SOURCE));

    let mut read = RedisRequestContext::without_exchange("case", &target, 0, "GET");
    read.recorded_at = DateTime::from_timestamp(1000, 0);
    read.actual_at = DateTime::from_timestamp(2000, 0);
    let prepared = owner
        .prepare_redis_time_read(
            &read,
            &keys,
            &keys,
            &source,
            DateTime::from_timestamp(1000, 0),
        )
        .unwrap()
        .unwrap();
    let mut write = RedisRequestContext::without_exchange("case", &target, 0, "SET");
    write.recorded_at = DateTime::from_timestamp(3000, 0);
    write.actual_at = DateTime::from_timestamp(7000, 0);
    let compare = |key| {
        owner
            .preview_redis_context(&write, &args(&[key, SOURCE]), &args(&[key, TARGET]))
            .unwrap()
    };
    assert!(compare("physical").is_err());
    assert!(!owner.has_time_copies("case"));
    prepared
        .publish(&rendered, DateTime::from_timestamp(2000, 0).unwrap())
        .unwrap();
    assert!(owner.has_time_copies("case"));
    assert!(compare("physical").is_err());
    assert!(compare("another-physical").is_err());
}
