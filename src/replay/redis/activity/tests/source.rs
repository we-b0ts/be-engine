//! Invalid complete Source lifetimes never install partial refresh permissions.
use super::*;

#[test]
fn activity_refresh_source_proof_rejects_business_mutations_ttl_readback_and_foreign_writers() {
    for scenario in [
        "business",
        "ttl",
        "readback",
        "format",
        "observer",
        "foreign",
        "missing-clock",
    ] {
        let (_root, mut state) = fixture(true);
        match scenario {
            "business" | "format" => {
                let mut next = value::decode(&state.exchanges[3].args[1]).unwrap();
                if scenario == "business" {
                    next["user_id"] = json!(99);
                } else {
                    next["last_activity_at"] = json!({"invalid":"type"});
                }
                state.exchanges[3].args[1] = serde_json::to_vec(&next).unwrap();
            }
            "ttl" => state.exchanges[3].args[3] = b"3601".to_vec(),
            "readback" => state.exchanges[2].response = b"$-1\r\n".to_vec(),
            "observer" | "foreign" => {
                let record = if scenario == "observer" {
                    event(10, "TTL", &[b"activity:1"], b":3599\r\n")
                } else {
                    event(
                        10,
                        "SET",
                        &[b"activity:1", b"foreign", b"EX", b"3600"],
                        b"+OK\r\n",
                    )
                };
                state
                    .register_exchange(
                        serde_json::from_value(record).unwrap(),
                        ReplaySource::Case,
                        Some("case"),
                        &mut BTreeMap::new(),
                        &[],
                    )
                    .unwrap();
                if scenario == "foreign" {
                    state.exchanges.last_mut().unwrap().source = ReplaySource::Startup;
                }
            }
            "missing-clock" => {
                state.exchanges[3].record.timestamp = None;
                state.exchanges[3].record.request_started_at = None;
            }
            _ => unreachable!(),
        }
        assert!(state.prepare_activity_case("case").is_err(), "{scenario}");
        assert!(state.activity_refresh.profiles.is_empty(), "{scenario}");
        assert!(state.activity_refresh.owned.is_empty(), "{scenario}");
    }
}

#[test]
fn activity_refresh_declaration_is_closed_and_does_not_allow_non_timestamp_fields() {
    for fields in [
        json!([]),
        json!(["/last_activity_at", "/last_activity_at"]),
        json!(["/*"]),
        json!([""]),
    ] {
        let mut policy = document(true);
        policy["redis"]["keys"]["activity:*"]["state"]["set"]["fields"] = fields;
        assert!(
            crate::policy::parse_policy(&policy.to_string())
                .and_then(|p| crate::policy::compile_policy(&p))
                .is_err()
        );
    }
    let mut policy = document(true);
    policy["redis"]["keys"]["activity:*"]["state"]["set"]["fields"] = json!(["/user_id"]);
    let (_root, mut state) = state_with_policy(&events(), policy);
    assert!(state.prepare_activity_case("case").is_err());
    assert!(state.activity_refresh.profiles.is_empty());
}
