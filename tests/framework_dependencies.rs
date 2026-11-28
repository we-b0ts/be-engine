//! Keep application installations outside the extracted framework libraries.
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

const MYSQL_SQL_CONTRACT: &str = "traffic-protocol-mysql-sql";

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
        "traffic-replay",
        "traffic-rewrite-core",
        "traffic-recorder",
        "traffic-recording-store",
        "traffic-model",
        "traffic-protocol",
        "traffic-value",
        "traffic-policy",
        "traffic-time",
    ]);
    let mysql_sql_contracts =
        BTreeSet::from([MYSQL_SQL_CONTRACT, "traffic-protocol", "traffic-model"]);
    for (framework, contracts) in [
        ("traffic-replay", &contracts),
        ("traffic-rewrite-core", &contracts),
        ("traffic-recorder", &contracts),
        ("traffic-recording-store", &contracts),
        (MYSQL_SQL_CONTRACT, &mysql_sql_contracts),
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

#[test]
fn service_libraries_keep_application_composition_above_them() {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version=1", "--no-deps", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for package in metadata["packages"].as_array().unwrap() {
        let name = package["name"].as_str().unwrap();
        if name.starts_with("traffic-protocol-") {
            for dependency in package["dependencies"].as_array().unwrap() {
                if dependency["kind"] == "dev" {
                    continue;
                }
                let dependency = dependency["name"].as_str().unwrap();
                assert!(
                    !dependency.starts_with("traffic-engine")
                        && !dependency.starts_with("traffic-rewrite")
                        && ![
                            "traffic-e2e",
                            "traffic-e2e-app",
                            "traffic-recorder",
                            "traffic-recording-store",
                            "traffic-replay-runtime"
                        ]
                        .contains(&dependency),
                    "native provider {name} depends on host-owned service {dependency}"
                );
                if name == MYSQL_SQL_CONTRACT {
                    // The shared protocol contracts supply the SQL operation type and use Tokio.
                    assert!(dependency != "tokio", "{name} must not use Tokio directly");
                }
            }
        }
        if ![
            "traffic-engine",
            "traffic-rewrite",
            "traffic-replay-runtime",
        ]
        .contains(&name)
        {
            continue;
        }
        for dependency in package["dependencies"].as_array().unwrap() {
            if dependency["kind"] == "dev" {
                continue;
            }
            let dependency = dependency["name"].as_str().unwrap();
            assert!(
                !["traffic-e2e", "traffic-e2e-app"].contains(&dependency),
                "{name} depends on application composition {dependency}"
            );
            if ["traffic-rewrite", "traffic-replay-runtime"].contains(&name) {
                assert!(
                    !dependency.starts_with("traffic-protocol-")
                        && !dependency.starts_with("traffic-codec-")
                        && !dependency.starts_with("traffic-policy-")
                        && dependency != "traffic-extensions",
                    "{name} directly installs a concrete implementation {dependency}"
                );
            }
            if name == "traffic-engine" {
                assert!(
                    ![
                        "traffic-rewrite",
                        "traffic-rewrite-core",
                        "traffic-replay-runtime"
                    ]
                    .contains(&dependency),
                    "engine services depend on an upper workflow/runtime owner {dependency}"
                );
            }
        }
    }
}

#[test]
fn standalone_services_skip_unrelated_runtime_dependencies() {
    for (package, excluded) in [
        (
            "traffic-engine-recording",
            &["traffic-engine-verification"][..],
        ),
        ("traffic-engine-e2e-run", &["traffic-engine-recording"]),
        (
            "traffic-replay-runtime",
            &[
                "traffic-engine",
                "traffic-engine-e2e-run",
                "traffic-engine-recording",
            ],
        ),
        (
            "traffic-rewrite-model",
            &[
                "traffic-engine",
                "traffic-engine-e2e-run",
                "traffic-engine-recording",
            ],
        ),
        (
            "traffic-rewrite-runtime",
            &[
                "traffic-engine",
                "traffic-engine-e2e-run",
                "traffic-engine-recording",
            ],
        ),
        ("traffic-rewrite-rules", &["traffic-engine"]),
        ("traffic-policy-schema", &["traffic-protocol-mysql"]),
        ("traffic-policy-compiler", &["traffic-protocol-mysql"]),
        ("traffic-policy-document", &["traffic-protocol-mysql"]),
        ("traffic-policy-content", &["traffic-protocol-mysql"]),
        (
            MYSQL_SQL_CONTRACT,
            &[
                "hyper",
                "rustls",
                "sqlx",
                "tokio-rustls",
                "tokio-tungstenite",
            ],
        ),
    ] {
        let output = Command::new(env!("CARGO"))
            .args([
                "tree",
                "--locked",
                "--package",
                package,
                "--edges",
                "normal,build",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for dependency in String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split_whitespace().next())
        {
            assert!(
                !excluded.contains(&dependency),
                "{package} pulls {dependency} into its production dependency tree"
            );
        }
    }
}
