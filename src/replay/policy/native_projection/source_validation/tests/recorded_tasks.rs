//! Private Source trace for the bulk-delete per-iteration Redis clock gap.
use super::*;
use crate::policy::native::{SequenceArgument, SequenceField};
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires TRAFFIC_E2E_SKIP_PROJECT and the original completed recording"]
fn recorded_tasks_delete_validates_per_call_redis_clocks_without_changing_evidence() {
    let root = std::path::PathBuf::from(std::env::var_os("TRAFFIC_E2E_SKIP_PROJECT").unwrap());
    let mut document = crate::policy::parse_policy(
        &std::fs::read_to_string(root.join(".traffic-e2e/policy.yaml")).unwrap(),
    )
    .unwrap();
    document
        .rules
        .retain(|rule| rule.id() == "tasks-delete-task-run-metrics-argv-times");
    assert_eq!(document.rules.len(), 1);
    let crate::policy::PolicyRule::Native(rule) = &mut document.rules[0] else {
        unreachable!()
    };
    let NativeEffect::RedisSequence(effect) = &mut rule.effect else {
        unreachable!()
    };
    for command in &mut effect.commands {
        for argument in command.arguments.values_mut() {
            match &mut argument.contract {
                SequenceArgument::Time(time) => {
                    time.anchor = crate::policy::TimeAnchor::DependencyRequestStart
                }
                SequenceArgument::Json { fields } => {
                    for field in fields.values_mut() {
                        if let SequenceField::Time(time) = &mut field.contract {
                            time.anchor = crate::policy::TimeAnchor::DependencyRequestStart;
                        }
                    }
                }
            }
        }
    }
    let policy = crate::policy::compile_policy(&document).unwrap();
    let recording =
        root.join(".traffic-e2e/local/artifacts/recordings/20261016030056/apis/api-tasks-wildcard");
    let mut cases = Vec::new();
    let mut digests = Vec::new();
    for entry in std::fs::read_dir(recording).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let request: Value =
            serde_json::from_slice(&std::fs::read(dir.join("request.json")).unwrap()).unwrap();
        if request["method"] != "DELETE" {
            continue;
        }
        let path = dir.join("dependencies.jsonl");
        let bytes = std::fs::read(&path).unwrap();
        digests.push((path, format!("{:x}", Sha256::digest(&bytes))));
        let events = bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        cases.push((
            dir.file_name().unwrap().to_str().unwrap().to_owned(),
            dir,
            request,
            events,
        ));
    }
    for prefix in ["e215f620", "a980f6ed"] {
        assert!(
            cases.iter().any(|(id, _, _, _)| id.starts_with(prefix)),
            "original bulk-delete case missing"
        );
    }
    let inputs = cases
        .iter()
        .map(|(id, dir, request, events)| NativeSourceCase {
            id,
            dir,
            request,
            events,
        })
        .collect::<Vec<_>>();
    let selected = policy
        .native
        .iter()
        .map(|rule| rule.rule.id.clone())
        .collect();
    let checked = validate_native_source_dependencies(&policy, &selected, &root, &inputs).unwrap();
    assert_eq!(checked.rules["tasks-delete-task-run-metrics-argv-times"], 6);
    for (path, digest) in digests {
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(path).unwrap())),
            digest
        );
    }
    println!(
        "original DELETE cases={}, Source Redis per-call validations={:?}; independent Target Replay remains required",
        cases.len(),
        checked.rules
    );
}
