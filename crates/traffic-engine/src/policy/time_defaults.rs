//! Compatibility export for shared field-policy settings.
pub use traffic_policy_value::fields::TimePolicy;

#[cfg(test)]
mod tests {
    use crate::value_contract::{global, json::AnchorClocks, time::ClockPair};
    use serde_json::json;

    #[test]
    fn timezone_is_runtime_semantics_without_changing_capture_identity() {
        let a = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
        let b = crate::policy::parse_and_compile_policy(
            "format: traffic-policy/v3\ntime: {default_utc_offset: '+00:00'}\n",
        )
        .unwrap();
        assert!(a.global_json.as_ref().unwrap().fields.is_empty());
        assert_ne!(a.fingerprints.runtime, b.fingerprints.runtime);
        assert_ne!(a.fingerprints.full, b.fingerprints.full);
        assert_eq!(a.fingerprints.capture, b.fingerprints.capture);
        assert_eq!(a.fingerprints.classification, b.fingerprints.classification);
        for offset in ["UTC", "+08:60", "+24:00", "8:00", "Asia/Shanghai"] {
            assert!(
                crate::policy::parse_and_compile_policy(&format!(
                    "format: traffic-policy/v3\ntime: {{default_utc_offset: '{offset}'}}\n"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn calendar_dates_use_the_configured_local_response_day_without_a_field_rule() {
        let source_clock = Some("2026-01-01T15:00:00Z".parse().unwrap());
        let target_clock = Some("2026-01-01T17:00:00Z".parse().unwrap());
        let clocks = AnchorClocks::for_response(
            ClockPair::default(),
            ClockPair {
                source: source_clock,
                target: target_clock,
            },
        );
        let check = |policy: &str| {
            let policy = crate::policy::parse_and_compile_policy(policy).unwrap();
            global::compare_logical(
                &json!({"date":"2026-01-01","strict":7}),
                &json!({"date":"2026-01-02","strict":7}),
                policy.global_json.as_ref().unwrap(),
                &[],
                clocks,
            )
            .unwrap()
        };
        let local = check("format: traffic-policy/v3\n");
        assert!(local.passed(), "{:?}", local.differences);
        assert!(local.pre_matches.is_empty());
        assert!(
            local
                .evaluated
                .contains(crate::value_contract::time::automatic::RULE_ID)
        );
        assert!(!local.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
        assert!(
            !check("format: traffic-policy/v3\ntime: {default_utc_offset: '+00:00'}\n").passed()
        );
    }
}
