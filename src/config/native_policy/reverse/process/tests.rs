use super::*;

#[test]
fn origin_script_exact_keys_roundtrip_without_authorizing_an_affix_middle() {
    let mut config = crate::config::SourceTrafficPolicyConfig::empty();
    config.process_owned_dependencies.push(serde_json::from_value(serde_json::json!({
        "name":"task-run-monitor","protocol":"redis","ports":[6379],"command":"EVALSHA",
        "source_revision":format!("sha256:{}", "1".repeat(64)),
        "source_evidence":"jobs.py:finish passes its captured task id and an exact as-of marker to Lua",
        "script":{"sha1":"a".repeat(40),"argv_count":1,"identity_argv_index":0,
            "keys":[{"prefix":"task-run:","suffix":":monitor","numeric_middle":true},
                {"prefix":"task-run-monitor:v2:","suffix":"as-of","numeric_middle":false}]},
        "trigger_source":{"kind":"api","method":"POST","path":"/jobs",
            "request_body_json":{"/background":true},
            "capture":{"job_id":{"protocol":"mysql","target_host":"db.test","target_port":3306,
                "database":"app","username":"writer","operation":"INSERT","tables":["jobs"],
                "row_match":{"role":"ASSISTANT"},"column":"id"}}}
    })).unwrap());
    let raw = crate::config::native_policy::render_initial(&config).unwrap();
    let typed = crate::policy::parse_policy(&raw).unwrap();
    let n::NativeEffect::ProcessOwned(effect) = &typed.rules[0].as_native().unwrap().effect else {
        panic!("wrong effect")
    };
    let n::ProcessSelector::Redis {
        script: Some(script),
        ..
    } = &effect.selector
    else {
        panic!("missing script")
    };
    assert!(matches!(
        &script.contract.keys[0],
        n::NativeKeySelector::Numeric { .. }
    ));
    assert_eq!(
        script.contract.keys[1],
        n::NativeKeySelector::Exact {
            value: "task-run-monitor:v2:as-of".into()
        }
    );
    let projected = crate::config::native_policy::parse_source_policy(&raw).unwrap();
    let B::Redis {
        script: Some(script),
        ..
    } = &projected.process_owned_dependencies[0]
    else {
        panic!("missing projected script")
    };
    let mut args = vec![
        "a".repeat(40).into_bytes(),
        b"2".to_vec(),
        b"task-run:12:monitor".to_vec(),
        b"task-run-monitor:v2:as-of".to_vec(),
        b"12".to_vec(),
    ];
    assert_eq!(script.check_identity(&args).unwrap(), "12");
    args[3] = b"task-run-monitor:v2:unexpected-as-of".to_vec();
    assert!(script.check_identity(&args).is_err());
}
