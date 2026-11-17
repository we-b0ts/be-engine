//! Keep application installations outside the extracted framework libraries.
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

#[test]
fn framework_production_dependencies_remain_implementation_independent() {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version=1", "--no-deps", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages: BTreeMap<_, _> = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| (package["name"].as_str().unwrap(), package))
        .collect();
    let contracts = BTreeSet::from([
        "traffic-engine",
        "traffic-rewrite-core",
        "traffic-recorder",
        "traffic-recording-store",
        "traffic-model",
        "traffic-protocol",
        "traffic-value",
        "traffic-policy",
        "traffic-time",
    ]);
    for framework in [
        "traffic-engine",
        "traffic-rewrite-core",
        "traffic-recorder",
        "traffic-recording-store",
    ] {
        let mut pending = vec![(framework, vec![framework])];
        let mut visited = BTreeSet::new();
        while let Some((name, chain)) = pending.pop() {
            if !visited.insert(name) {
                continue;
            }
            assert!(
                contracts.contains(name),
                "framework implementation dependency {}",
                chain.join(" -> ")
            );
            for dependency in packages[name]["dependencies"].as_array().unwrap() {
                if dependency["kind"] == "dev" || dependency["path"].is_null() {
                    continue;
                }
                let dependency_name = dependency["name"].as_str().unwrap();
                let mut dependency_chain = chain.clone();
                dependency_chain.push(dependency_name);
                pending.push((dependency_name, dependency_chain));
            }
        }
    }
}
