//! Independently scheduled Redis scripts use the ordinary finite Source proof.
use super::super::source;
use super::*;
use crate::config::native_policy::{NativeSourceScope, SourceObligation, validate_source};
use crate::protocols::recording::events::{RecorderEvent, RedisExchangeEvent};
use crate::recorder::{Recorder, capture_body};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[tokio::test]
async fn sealed_process_eval_selects_only_its_endpoint_script_and_ordered_keys() {
    const SCRIPT: &str = "return #KEYS";
    let sha256 = format!("{:x}", Sha256::digest(SCRIPT));
    let document = format!(
        r#"format: traffic-policy/v3
process_dependencies:
  tasks:
    claim_pending:
      requests:
        - redis:
            operation: EVAL
            resource: {{protocol: redis, endpoint: cache.test:6379, database: 0}}
            script: {{sha256: {sha256}}}
            keys: [task:pending, task:claimed]
"#
    );
    let policy = crate::policy::parse_and_compile_policy(&document).unwrap();
    let projected = crate::config::native_policy::project_source_policy(&policy.native).unwrap();
    let rule = &projected.process_owned_dependencies[0];
    assert!(!rule.uses_redis_snapshot());
    let target = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(target.path().join("recordings"))
        .await
        .unwrap();
    let connection = Uuid::new_v4();
    // Oversized selector metadata takes the original-record path. Its ARGV
    // differs, so both occurrences also test exact KEYS rather than all args.
    let large_argument = "x".repeat(70 * 1024);
    for (index, (script, host, database, keys, argument)) in [
        (
            SCRIPT,
            "cache.test",
            0,
            ["task:pending", "task:claimed"],
            "1",
        ),
        (
            SCRIPT,
            "cache.test",
            0,
            ["task:pending", "task:claimed"],
            large_argument.as_str(),
        ),
        (
            "return 2",
            "cache.test",
            0,
            ["task:pending", "task:claimed"],
            "1",
        ),
        (
            SCRIPT,
            "other.test",
            0,
            ["task:pending", "task:claimed"],
            "1",
        ),
        (
            SCRIPT,
            "cache.test",
            1,
            ["task:pending", "task:claimed"],
            "1",
        ),
        (
            SCRIPT,
            "cache.test",
            0,
            ["task:claimed", "task:pending"],
            "1",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let now = chrono::Utc::now();
        let endpoint = format!("{host}:6379");
        let exchange = RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: connection,
            sequence: index as u64 + 1,
            timestamp: now,
            request_started_at: now,
            client_addr: None,
            target_host: host.into(),
            target_port: 6379,
            target_addr: endpoint.clone(),
            upstream_addr: endpoint,
            resp_version: 2,
            database,
            username: None,
            command: "EVAL".into(),
            args: [script, "2", keys[0], keys[1], argument]
                .into_iter()
                .map(|arg| capture_body(arg.as_bytes(), arg.len()))
                .collect(),
            response_kind: "integer".into(),
            response: capture_body(b":2\r\n", 4),
            rpc_callback_capture: None,
            cache_snapshot_rule: None,
            cache_snapshot_hit: false,
            session_setup: false,
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 1,
            replay_safe: true,
            parse_warnings: vec![],
        });
        assert_eq!(rule.matches(&exchange), index < 2);
        recorder
            .append_global_dependency(&exchange, "outside_admission", "runtime", "")
            .await
            .unwrap();
    }
    recorder.finish_run().await.unwrap();
    let mut state = crate::test_state();
    let case_source = recorder.run_dir().as_path();
    state.case_source = Some(case_source.to_path_buf());
    state.recording_run_id = case_source.file_name().unwrap().to_str().unwrap().into();
    state.source_revision = Some("test-source".into());

    let original = source::load(&state).unwrap();
    let attributed = process_matches(&original, &policy.native, None).unwrap();
    assert_eq!(
        attributed
            .iter()
            .map(|id| original.exchanges[id].selector["sequence"]
                .as_u64()
                .unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 2])
    );
    let validation = validate_source(
        NativeSourceScope {
            target_root: target.path(),
            case_source,
            source_revision: "test-source",
            recording_run_id: &state.recording_run_id,
            prepared_cases: &BTreeMap::new(),
            replay_report: None,
            policy_rules: &policy.native,
        },
        &policy.native,
    )
    .unwrap();
    assert_eq!(validation.rules[rule.name()], 2);
    assert_eq!(
        validation.obligations,
        BTreeSet::from([SourceObligation::AttributionReview])
    );
}
