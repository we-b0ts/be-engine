//! Opt-in Source acceptance; project permission and Target certification stay external.
use super::*;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires TRAFFIC_E2E_OBSERVATION_CASES, TRAFFIC_E2E_OBSERVATION_READ_PREFIXES and TRAFFIC_E2E_OBSERVATION_EXPIRY_PREFIX"]
fn recorded_observation_lifetimes_validate_without_editing_source() {
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_OBSERVATION_CASES").unwrap());
    let prefixes: Vec<String> =
        serde_json::from_str(&std::env::var("TRAFFIC_E2E_OBSERVATION_READ_PREFIXES").unwrap())
            .unwrap();
    let expiry_prefix = std::env::var("TRAFFIC_E2E_OBSERVATION_EXPIRY_PREFIX").unwrap();
    assert!(
        !prefixes.is_empty() && prefixes.iter().all(|p| !p.is_empty()) && !expiry_prefix.is_empty()
    );
    let mut inventory = Vec::new();
    let mut originals = Vec::new();
    let mut rules = BTreeMap::new();
    for dir in fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("dependencies.jsonl").is_file())
    {
        let path = dir.join("dependencies.jsonl");
        let bytes = fs::read(&path).unwrap();
        let request_path = dir.join("request.json");
        let request_bytes = fs::read(&request_path).unwrap();
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        let events = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Value>(l).unwrap())
            .collect::<Vec<_>>();
        let api = format!(
            "{} {}",
            request["method"].as_str().unwrap(),
            request["uri"].as_str().unwrap().split('?').next().unwrap()
        );
        for e in events.iter().filter(|e| {
            e["event_type"] == "redis_exchange"
                && matches!(e["command"].as_str(), Some("GET" | "EXPIRE"))
        }) {
            let key = crate::api_trigger::decode(&e["args"][0]).unwrap();
            let prefix = if e["command"] == "GET" {
                prefixes.iter().find(|p| key.starts_with(p.as_bytes()))
            } else {
                key.starts_with(expiry_prefix.as_bytes())
                    .then_some(&expiry_prefix)
            };
            let Some(prefix) = prefix else {
                continue;
            };
            let mut resource = json!({"protocol":"redis","endpoint":format!("{}:{}",e["target_host"].as_str().unwrap(),e["target_port"]),"database":e["database"]});
            if let Some(user) = e["username"].as_str() {
                resource["username"] = json!(user);
            }
            let id = crate::policy_evidence::digest(
                &serde_json::to_vec(&json!([api, resource, prefix, e["command"]])).unwrap(),
            );
            let id = format!("observations-{}", id.trim_start_matches("sha256:"));
            let effect = if e["command"] == "GET" {
                json!({"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},"references":[{"resource":resource}],
                "read_back":[{"operation":"GET","write_operation":"SET","argument_index":1,"state_epochs":{"source":"caller-selected immutable Source trace","fact":"Source acceptance checks SET/DEL state observations without authorizing project policy"}}]})
            } else {
                json!({"kind":"redis_expiry_refresh"})
            };
            rules.insert(id.clone(),json!({"id":id,"match":{"api":api,"resource":resource,"operation":if e["command"]=="GET" {"SET"}else{"EXPIRE"},"key":{"kind":"affix","prefix":prefix}},"effect":effect,
                "proof":{"source":"caller-selected immutable Source trace","fact":"Read-only Source acceptance; creates no project permission or Target certification"}}));
        }
        originals.extend([(path, bytes), (request_path, request_bytes)]);
        inventory.push((
            dir.file_name().unwrap().to_str().unwrap().to_owned(),
            dir,
            request,
            events,
        ));
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
        .map(
            |(id, dir, request, events)| crate::replay::NativeSourceCase {
                id,
                dir,
                request,
                events,
            },
        )
        .collect::<Vec<_>>();
    let temp = tempfile::tempdir().unwrap();
    let checked = crate::replay::validate_native_source_dependencies(
        &compiled,
        &compiled.native.iter().map(|r| r.rule.id.clone()).collect(),
        temp.path(),
        &cases,
    )
    .unwrap();
    assert_eq!(checked.rules.len(), compiled.native.len());
    assert!(checked.rules.values().all(|c| *c > 0));
    eprintln!(
        "Source state observations: {} Cases, {} rule scopes, {} Source validations",
        cases.len(),
        checked.rules.len(),
        checked.rules.values().sum::<usize>()
    );
    for (path, bytes) in originals {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
