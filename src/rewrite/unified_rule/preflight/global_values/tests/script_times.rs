//! Existing script clocks remain usable while a separate JSON format is added.
use super::*;

const HASH: &str = "75f75be3d11e483c99c83f8b0b8836c2e2c5923b";
fn script_policy() -> CompiledPolicy {
    crate::policy::parse_and_compile_policy(&format!(
        r#"format: traffic-policy/v3
json:
  fields:
    /at: {{kind: time, formats: [unix_seconds]}}
redis:
  keys:
    'metrics:*':
      commands:
        - operation: EVALSHA
          script: {{sha1: {HASH}}}
          arguments:
            3: {{kind: time, formats: [unix_seconds]}}
            4: {{kind: time, formats: [unix_microseconds]}}
            6: {{kind: time, formats: [unix_seconds]}}
"#
    ))
    .unwrap()
}
fn command(seconds: i64) -> Vec<Vec<u8>> {
    [
        HASH.to_string(),
        "1".into(),
        "metrics:one".into(),
        seconds.to_string(),
        (seconds * 1_000_000).to_string(),
        json!({"at":seconds,"stable":7}).to_string(),
        seconds.to_string(),
        "strict-control".into(),
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect()
}
fn check(source: &[Vec<u8>], target: &[Vec<u8>], clocks: AnchorClocks) -> Result<Comparison> {
    let policy = script_policy();
    let request = json!({"method":"POST","uri":"/api"});
    let event = json!({"event_type":"redis_exchange","command":"EVALSHA",
        "target_host":"redis.test","target_port":6379,"database":0});
    let mut obligations = BTreeSet::new();
    redis::compare(
        &event,
        Surface::DependencyRequest,
        &serde_json::to_vec(source)?,
        &serde_json::to_vec(target)?,
        &mut CompareContext {
            policy: &policy,
            clocks,
            metadata: &Default::default(),
            copies: None,
            request: Some(&request),
            native_obligations: &mut obligations,
        },
    )
}
fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    }
}
#[test]
fn global_json_preflight_composes_existing_script_time_contracts() {
    let checked = check(&command(1000), &command(2000), clocks()).unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
    assert!(checked.evaluated.contains(GLOBAL_JSON_ID));
    assert!(checked.evaluated.len() > 1);
}
#[test]
fn script_time_composition_preserves_identity_argv_and_independent_clock_guards() {
    let source = command(1000);
    for index in [0, 1, 2, 7] {
        let mut target = command(2000);
        target[index] = b"changed".to_vec();
        assert!(
            check(&source, &target, clocks()).is_err(),
            "argument {index}"
        );
    }
    for index in [3, 4, 6] {
        let mut target = command(2000);
        target[index] = b"9999999999".to_vec();
        assert!(
            !check(&source, &target, clocks()).unwrap().passed(),
            "time {index}"
        );
    }
    let mut target = command(2000);
    target[5] = json!({"at":2000,"stable":8}).to_string().into_bytes();
    assert!(!check(&source, &target, clocks()).unwrap().passed());
    assert!(
        !check(&source, &command(2000), Default::default())
            .unwrap()
            .passed()
    );
    let mut other_source = source.clone();
    other_source[2] = b"unselected:one".to_vec();
    let mut other_target = command(2000);
    other_target[2] = b"unselected:one".to_vec();
    assert!(check(&other_source, &other_target, clocks()).is_err());
}

#[test]
fn unrelated_zero_key_scripts_keep_their_existing_global_payload_contract() {
    let policy = script_policy();
    let request = json!({"method":"POST","uri":"/api"});
    let event = json!({"event_type":"redis_exchange","command":"EVALSHA"});
    let source = args(&[HASH, "0", r#"{"at":1000,"stable":7}"#]);
    let target = args(&[HASH, "0", r#"{"at":2000,"stable":7}"#]);
    let mut obligations = BTreeSet::new();
    let checked = redis::compare(
        &event,
        Surface::DependencyRequest,
        &source,
        &target,
        &mut CompareContext {
            policy: &policy,
            clocks: clocks(),
            metadata: &Default::default(),
            copies: None,
            request: Some(&request),
            native_obligations: &mut obligations,
        },
    )
    .unwrap();
    assert!(checked.passed(), "{:?}", checked.differences);
}
