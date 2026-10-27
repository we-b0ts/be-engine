//! Read-only opt-in acceptance against caller-selected immutable Source evidence.
use super::*;
use std::{fs, path::PathBuf};

#[test]
#[ignore = "requires TRAFFIC_E2E_ACTIVITY_CASES and TRAFFIC_E2E_ACTIVITY_POLICY"]
fn recorded_activity_refresh_validates_complete_source_without_editing_evidence() {
    let root = PathBuf::from(std::env::var_os("TRAFFIC_E2E_ACTIVITY_CASES").unwrap());
    let policy = PathBuf::from(std::env::var_os("TRAFFIC_E2E_ACTIVITY_POLICY").unwrap());
    let compiled = crate::policy::parse_policy(&fs::read_to_string(policy).unwrap())
        .and_then(|p| crate::policy::compile_policy(&p))
        .unwrap();
    let mut inventory = Vec::new();
    let mut originals = Vec::new();
    for dir in fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("dependencies.jsonl").is_file())
    {
        let trace = dir.join("dependencies.jsonl");
        let request_path = dir.join("request.json");
        let bytes = fs::read(&trace).unwrap();
        let request = fs::read(&request_path).unwrap();
        let events = bytes
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice::<Value>(l).unwrap())
            .collect::<Vec<_>>();
        inventory.push((
            dir.file_name().unwrap().to_str().unwrap().to_owned(),
            dir,
            serde_json::from_slice::<Value>(&request).unwrap(),
            events,
        ));
        originals.extend([(trace, bytes), (request_path, request)]);
    }
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
    assert!(checked.rules.values().all(|&n| n > 0));
    eprintln!(
        "activity Source proof: {} cases, {} rule scopes, {} validations",
        cases.len(),
        checked.rules.len(),
        checked.rules.values().sum::<usize>()
    );
    for (path, bytes) in originals {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
