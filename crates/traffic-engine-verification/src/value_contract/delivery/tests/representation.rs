use super::*;

#[test]
fn standard_text_delivery_preserves_source_fraction_width_and_timezone_spelling() {
    let settings = crate::policy::TimePolicy::default();
    for (source, target) in [
        ("2020-01-01T00:00:00Z", "2020-01-01T00:00:01Z"),
        ("2020-01-01T00:00:00.0Z", "2020-01-01T00:00:01.2Z"),
        ("2020-01-01T00:00:00.000Z", "2020-01-01T00:00:01.234Z"),
        (
            "2020-01-01T00:00:00.000000+00:00",
            "2020-01-01T00:00:01.234567+00:00",
        ),
        (
            "2020-01-01T08:00:00.000000000+08:00",
            "2020-01-01T08:00:01.234567890+08:00",
        ),
        ("2020-01-01t00:00:00.000z", "2020-01-01t00:00:01.234z"),
        ("2020-01-01T08:00:00.000000", "2020-01-01T08:00:01.234567"),
        ("2020-01-01 08:00:00.000000", "2020-01-01 08:00:01.234567"),
    ] {
        let source = json!(source);
        let contract = crate::value_contract::time::automatic::contract(&source, &settings)
            .unwrap()
            .time()
            .unwrap();
        let delivered = shift(&source, &contract, 1_234_567_890).unwrap();
        assert_eq!(delivered, json!(target));
        crate::value_contract::json::parse_time_pair(&source, &delivered, &contract).unwrap();
    }
}

#[test]
fn explicitly_grouped_text_fields_share_one_representable_shift() {
    let rule: crate::policy::Rule = serde_json::from_value(json!({
        "id":"same-clock", "surface":"dependency.response",
        "match":{"resource":{"protocol":"redis","endpoint":"cache:6379"},"operation":"GET","key":{"exact":"clock"}},
        "slot":"value","codec":"json",
        "contract":{
            "/whole":{"kind":"time","format":"rfc3339","relation":"preserve_offset","clock_group":"same"},
            "/micro":{"kind":"time","format":"rfc3339","relation":"preserve_offset","clock_group":"same"}
        },
        "delivery":{"rebase_time":["/whole","/micro"]},
        "proof":{"source":"service.py:clock","fact":"Both fields copy the same clock read."}
    })).unwrap();
    let rule = crate::policy::compile_rule(&rule).unwrap();
    let source = json!({"whole":"2020-01-01T00:00:00Z","micro":"2020-01-01T00:00:00.000000Z"});
    let clocks = AnchorClocks::for_request(
        Default::default(),
        ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2021-01-01T00:00:00.456789Z".parse().unwrap()),
        },
        Default::default(),
    );
    let output = materialize(&source, &[&rule], clocks).unwrap();
    assert_eq!(
        output,
        json!({"whole":"2021-01-01T00:00:00Z","micro":"2021-01-01T00:00:00.000000Z"})
    );
}
