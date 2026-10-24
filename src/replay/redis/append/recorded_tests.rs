//! Opt-in read-only acceptance on caller-selected immutable recording Cases.
use super::*;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires TRAFFIC_E2E_APPEND_CASES pointing to an immutable API recording directory"]
fn recorded_append_source_traces_validate_without_changing_recordings() {
    let cases_root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_APPEND_CASES").unwrap());
    let mut directories = fs::read_dir(&cases_root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("dependencies.jsonl").is_file())
        .collect::<Vec<_>>();
    directories.sort();
    let mut originals = Vec::new();
    let mut inventory = Vec::new();
    let mut rules = BTreeMap::new();
    let mut replay_cases = BTreeMap::new();
    for directory in directories {
        let dependency = directory.join("dependencies.jsonl");
        let request_path = directory.join("request.json");
        let bytes = fs::read(&dependency).unwrap();
        let request_bytes = fs::read(&request_path).unwrap();
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        let events = bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        let api = format!(
            "{} {}",
            request["method"].as_str().unwrap(),
            request["uri"].as_str().unwrap().split('?').next().unwrap()
        );
        for event in events
            .iter()
            .filter(|e| e["event_type"] == "redis_exchange" && e["command"] == "APPEND")
        {
            let key = crate::api_trigger::decode(&event["args"][0]).unwrap();
            let identity = crate::policy_evidence::digest(
                &serde_json::to_vec(&json!([
                    api,
                    event["target_host"],
                    event["target_port"],
                    event["database"],
                    event["username"],
                    key
                ]))
                .unwrap(),
            );
            let id = format!("append-{}", identity.trim_start_matches("sha256:"));
            let mut resource = json!({"protocol":"redis","endpoint":format!("{}:{}",event["target_host"].as_str().unwrap(),event["target_port"]),"database":event["database"]});
            if let Some(username) = event["username"].as_str() {
                resource["username"] = json!(username);
            }
            rules.insert(id.clone(),json!({"id":id,"match":{"api":api,"resource":resource,"operation":"APPEND","key":{"kind":"exact","value":String::from_utf8(key).unwrap()}},
                "effect":{"kind":"redis_append_stream"},"proof":{"source":"caller-selected immutable Source trace","fact":"Read-only engine acceptance checks each cumulative byte length, observation/reset fence and writer ordering; this test creates no project permission"}}));
        }
        let id = directory.file_name().unwrap().to_str().unwrap().to_owned();
        replay_cases.insert(
            id.clone(),
            crate::replay::ReplayCase {
                id: id.clone(),
                dir: directory.clone(),
                dependencies_path: dependency.clone(),
                status: crate::replay::ReplayCaseStatus::Pending,
            },
        );
        originals.extend([(dependency, bytes), (request_path, request_bytes)]);
        inventory.push((id, directory, request, events));
    }
    assert!(!rules.is_empty());
    let document =
        json!({"format":"traffic-policy/v2","rules":rules.into_values().collect::<Vec<_>>()});
    let compiled =
        crate::policy::compile_policy(&crate::policy::parse_policy(&document.to_string()).unwrap())
            .unwrap();
    let cases = inventory
        .iter()
        .map(
            |(id, dir, request, events)| crate::replay::NativeSourceCase {
                id,
                dir,
                request,
                events,
            },
        )
        .collect::<Vec<_>>();
    let root = tempfile::tempdir().unwrap();
    let checked = crate::replay::validate_native_source_dependencies(
        &compiled,
        &compiled.native.iter().map(|r| r.rule.id.clone()).collect(),
        root.path(),
        &cases,
    )
    .unwrap();
    let path = root.path().join("policy.yaml");
    fs::write(&path, document.to_string()).unwrap();
    let runtime = crate::replay::ReplayPolicyRuntime::load(&path, &replay_cases).unwrap();
    let mut state = RedisReplayState {
        request_contracts: runtime.request_contracts.clone(),
        ..Default::default()
    };
    let mut targets = BTreeMap::new();
    for (id, _, _, events) in &inventory {
        for event in events
            .iter()
            .filter(|e| e["event_type"] == "redis_exchange")
        {
            state
                .register_exchange(
                    serde_json::from_value(event.clone()).unwrap(),
                    ReplaySource::Case,
                    Some(id),
                    &mut targets,
                    &[],
                )
                .unwrap();
        }
    }
    for (id, _, _, _) in &inventory {
        state.prepare_append_case(id).unwrap();
    }
    let global = cases_root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("global-dependencies.jsonl");
    if global.is_file() {
        let bytes = fs::read(&global).unwrap();
        for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let event: Value = serde_json::from_slice(line).unwrap();
            if event["event_type"] != "redis_exchange" {
                continue;
            }
            let args = event["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| crate::api_trigger::decode(v).unwrap())
                .collect::<Vec<_>>();
            for profile in &state.append_streams.profiles {
                if event["target_host"].as_str() == Some(profile.target.host.as_str())
                    && event["target_port"].as_u64() == Some(profile.target.port.into())
                    && event["database"].as_i64() == Some(profile.database)
                {
                    assert!(
                        !trace::touches(event["command"].as_str().unwrap(), &args, &profile.key),
                        "Global key overlap"
                    );
                }
            }
        }
        assert_eq!(fs::read(global).unwrap(), bytes);
    }
    for (path, bytes) in originals {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    eprintln!(
        "validated {} Cases, {} streams, {} Source APPENDs",
        inventory.len(),
        state.append_streams.profiles.len(),
        checked.rules.values().sum::<usize>()
    );
}
