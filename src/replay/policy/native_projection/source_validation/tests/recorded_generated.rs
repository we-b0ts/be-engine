//! Opt-in Source-only acceptance against the two original skipped API recordings.
use super::*;
use sha2::{Digest, Sha256};

fn args(event: &Value) -> Vec<Vec<u8>> {
    event["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| crate::api_trigger::decode(v).unwrap())
        .collect()
}

fn rule(id: &str, api: &str, event: &Value, key: Value, effect: Value) -> Value {
    json!({"id":id,"match":{"api":api,"resource":{"protocol":"redis","endpoint":format!("{}:{}",event["target_host"].as_str().unwrap(),event["target_port"]),"database":event["database"],"username":event["username"]},"key":key},
        "effect":effect,"proof":{"source":"app/services/device/capability_sync_service.py:plugin_package_storage.presign_download; celery/app/base.py:send_task; kombu/transport/virtual/base.py:publish","fact":"Source signs per-plugin URLs with UTC credential dates and independent expiry reads; Celery captures a task UUID in its result channel and references it in LPUSH while generating delivery, reply and origin metadata"}})
}

#[test]
#[ignore = "requires TRAFFIC_E2E_SKIP_PROJECT and the immutable 20261016030056 recording"]
fn recorded_generated_rpc_and_celery_source_contracts_validate_without_changing_recordings() {
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_SKIP_PROJECT").unwrap());
    let recording = root.join(".traffic-e2e/local/artifacts/recordings/20261016030056/apis");
    let mut counts = BTreeMap::<&str, usize>::new();
    for (api_dir, kind) in [
        ("api-plugins-installed-sync-device", "rpc"),
        ("api-internal-conversion-callback-completed", "celery"),
    ] {
        for entry in std::fs::read_dir(recording.join(api_dir)).unwrap() {
            let dir = entry.unwrap().path();
            let path = dir.join("dependencies.jsonl");
            if !path.is_file() {
                continue;
            }
            let original = std::fs::read(&path).unwrap();
            let digest = Sha256::digest(&original);
            let events = original
                .split(|b| *b == b'\n')
                .filter(|v| !v.is_empty())
                .map(|v| serde_json::from_slice::<Value>(v).unwrap())
                .collect::<Vec<_>>();
            let request: Value =
                serde_json::from_slice(&std::fs::read(dir.join("request.json")).unwrap()).unwrap();
            let api = format!(
                "{} {}",
                request["method"].as_str().unwrap(),
                request["uri"].as_str().unwrap().split('?').next().unwrap()
            );
            let rules = if kind == "rpc" {
                let Some(publish) = events.iter().find(|event| {
                    event["event_type"] == "redis_exchange" && event["command"] == "PUBLISH"
                }) else {
                    continue;
                };
                let values = args(publish);
                vec![rule(
                    "rpc-downloads",
                    &api,
                    publish,
                    json!({"kind":"exact","value":String::from_utf8(values[0].clone()).unwrap()}),
                    json!({"kind":"redis_sequence","commands":[{"operation":"PUBLISH","arguments":{"1":{"kind":"json","fields":{
                        "/data/0/plugins/*/download_path":{"kind":"url","query":{
                            "X-Amz-Date":{"kind":"time","format":"amz_date","relation":"preserve_offset","clock_group":"signing"},
                            "X-Amz-Credential":{"kind":"utc_date_segment","separator":"/","index":1,"relative_to":"X-Amz-Date"},
                            "X-Amz-Signature":{"kind":"random","format":"hex","length":64}
                        }},
                        "/data/0/plugins/*/download_url_expires_at":{"kind":"time","format":"rfc3339","relation":"preserve_offset","clock_group":"expiry"}
                    }}}}]}),
                )]
            } else {
                let subscribe = events.iter().find(|e| e["command"] == "SUBSCRIBE").unwrap();
                let publish = events.iter().find(|e| e["command"] == "LPUSH").unwrap();
                let queue = String::from_utf8(args(publish)[0].clone()).unwrap();
                vec![
                    rule(
                        "result-channel",
                        &api,
                        subscribe,
                        json!({"kind":"affix","prefix":"celery-task-meta-"}),
                        json!({"kind":"redis_sequence","key":{"kind":"capture","template":"celery-task-meta-{value}","format":{"kind":"uuid_v4"}},"commands":[{"operation":"SUBSCRIBE","arguments":{}},{"operation":"UNSUBSCRIBE","arguments":{}}]}),
                    ),
                    rule(
                        "queued-task",
                        &api,
                        publish,
                        json!({"kind":"exact","value":queue}),
                        json!({"kind":"redis_sequence","commands":[{"operation":"LPUSH","arguments":{"1":{"kind":"json","fields":{
                            "/headers/id":{"kind":"identity","template":"{value}","transform":"identity"},
                            "/headers/root_id":{"kind":"identity","template":"{value}","transform":"identity"},
                            "/properties/correlation_id":{"kind":"identity","template":"{value}","transform":"identity"},
                            "/properties/delivery_tag":{"kind":"random","format":"uuid","length":36},
                            "/properties/reply_to":{"kind":"random","format":"uuid","length":36},
                            "/headers/origin":{"kind":"random","format":"string","max_length":255}
                        }}}}]}),
                    ),
                ]
            };
            let document = crate::policy::parse_policy(
                &json!({"format":"traffic-policy/v2","rules":rules}).to_string(),
            )
            .unwrap();
            let compiled = crate::policy::compile_policy(&document).unwrap();
            let selected = compiled
                .native
                .iter()
                .map(|rule| rule.rule.id.clone())
                .collect();
            let id = dir.file_name().unwrap().to_str().unwrap();
            let checked = validate_native_source_dependencies(
                &compiled,
                &selected,
                &root,
                &[NativeSourceCase {
                    id,
                    dir: &dir,
                    request: &request,
                    events: &events,
                }],
            )
            .unwrap();
            assert!(checked.rules.values().all(|count| *count > 0));
            assert_eq!(digest, Sha256::digest(std::fs::read(&path).unwrap()));
            *counts.entry(kind).or_default() += 1;
        }
    }
    assert!(counts["rpc"] >= 1 && counts["celery"] >= 1);
    println!(
        "Original Source contracts validated for {counts:?}; independent Target Replay remains required"
    );
}
