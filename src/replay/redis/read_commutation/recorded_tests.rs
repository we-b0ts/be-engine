//! Opt-in acceptance on caller-selected immutable Source evidence.
use super::*;
use crate::replay::policy::native_projection::NativeSourceCase;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires TRAFFIC_E2E_READ_COMMUTATION_CASES and TRAFFIC_E2E_READ_COMMUTATION_PREFIX"]
fn recorded_read_commutation_proves_complete_scoped_keys_without_editing_source() {
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_READ_COMMUTATION_CASES").unwrap());
    let prefix = std::env::var("TRAFFIC_E2E_READ_COMMUTATION_PREFIX").unwrap();
    assert!(!prefix.is_empty());
    let mut inventory = Vec::new();
    let mut originals = Vec::new();
    let mut rules = BTreeMap::new();
    for directory in fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("dependencies.jsonl").is_file())
    {
        let path = directory.join("dependencies.jsonl");
        let bytes = fs::read(&path).unwrap();
        let request_path = directory.join("request.json");
        let request_bytes = fs::read(&request_path).unwrap();
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        let events = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Value>(l).unwrap())
            .collect::<Vec<_>>();
        for event in events
            .iter()
            .filter(|e| e["event_type"] == "redis_exchange" && e["command"] == "GET")
        {
            let key = crate::api_trigger::decode(&event["args"][0]).unwrap();
            if !key.starts_with(prefix.as_bytes()) {
                continue;
            }
            let id = format!(
                "read-{}",
                crate::policy_evidence::digest(&key).trim_start_matches("sha256:")
            );
            let mut resource = json!({"protocol":"redis","endpoint":format!("{}:{}",event["target_host"].as_str().unwrap(),event["target_port"]),"database":event["database"]});
            if let Some(user) = event["username"].as_str() {
                resource["username"] = json!(user);
            }
            rules.insert(id.clone(),json!({"id":id,"match":{"api":format!("{} {}",request["method"].as_str().unwrap(),request["uri"].as_str().unwrap().split('?').next().unwrap()),"resource":resource,"operation":"GET","key":{"kind":"exact","value":String::from_utf8(key).unwrap()}},"effect":{"kind":"redis_read_commutation"},"proof":{"source":"caller-selected immutable Source inventory","fact":"Read-only acceptance validates every selected observation and key access; it grants no project policy permission"}}));
        }
        let id = directory.file_name().unwrap().to_str().unwrap().to_owned();
        originals.extend([(path, bytes), (request_path, request_bytes)]);
        inventory.push((id, directory, request, events));
    }
    assert!(!rules.is_empty());
    let compiled = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v1","rules":rules.into_values().collect::<Vec<_>>()} )
            .to_string(),
    )
    .and_then(|p| crate::policy::compile_policy(&p))
    .unwrap();
    let cases = inventory
        .iter()
        .map(|(id, dir, request, events)| NativeSourceCase {
            id,
            dir,
            request,
            events,
        })
        .collect::<Vec<_>>();
    let temporary = tempfile::tempdir().unwrap();
    let checked = crate::replay::validate_native_source_dependencies(
        &compiled,
        &compiled.native.iter().map(|r| r.rule.id.clone()).collect(),
        temporary.path(),
        &cases,
    )
    .unwrap();
    assert_eq!(checked.rules.len(), compiled.native.len());
    assert!(checked.rules.values().all(|count| *count > 0));
    eprintln!(
        "Source read commutation: {} keys, {} finite reads",
        checked.rules.len(),
        checked.rules.values().sum::<usize>()
    );
    for (path, bytes) in originals {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
