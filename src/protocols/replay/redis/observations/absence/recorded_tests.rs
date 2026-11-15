//! Read-only acceptance against caller-selected immutable recording inventories.
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires TRAFFIC_E2E_ABSENT_READ_CASES and TRAFFIC_E2E_ABSENT_READ_PREFIX"]
fn recorded_absent_reads_validate_without_editing_source() {
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_ABSENT_READ_CASES").unwrap());
    let prefix = std::env::var("TRAFFIC_E2E_ABSENT_READ_PREFIX").unwrap();
    assert!(!prefix.is_empty() && !prefix.contains('*'));
    let mut inventory = Vec::new();
    let mut originals = Vec::new();
    for dir in fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|dir| dir.join("dependencies.jsonl").is_file())
    {
        let path = dir.join("dependencies.jsonl");
        let bytes = fs::read(&path).unwrap();
        let request_path = dir.join("request.json");
        let request_bytes = fs::read(&request_path).unwrap();
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        let events = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        originals.extend([(path, bytes), (request_path, request_bytes)]);
        inventory.push((
            dir.file_name().unwrap().to_str().unwrap().to_owned(),
            dir,
            request,
            events,
        ));
    }
    assert!(!inventory.is_empty());
    let policy = crate::policy::parse_policy(
        &json!({"format":"traffic-policy/v3",
        "redis":{"keys":{format!("{prefix}*"):{"state":{"get":{"transient":["nil"]}}}}}})
        .to_string(),
    )
    .unwrap();
    let compiled = crate::policy::compile_policy(&policy).unwrap();
    let cases = inventory
        .iter()
        .map(
            |(id, dir, request, events)| crate::policy::runtime::NativeSourceCase {
                id,
                dir,
                request,
                events,
            },
        )
        .collect::<Vec<_>>();
    let temporary = tempfile::tempdir().unwrap();
    let checked = crate::policy::runtime::validate_native_source_dependencies(
        &compiled,
        &compiled
            .native
            .iter()
            .map(|rule| rule.rule.id.clone())
            .collect(),
        temporary.path(),
        &cases,
    )
    .unwrap();
    assert_eq!(checked.rules.len(), 1);
    assert!(checked.rules.values().all(|count| *count > 0));
    eprintln!(
        "Absent read Source acceptance: {} Cases, {} observations",
        cases.len(),
        checked.rules.values().sum::<usize>()
    );
    for (path, bytes) in originals {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
