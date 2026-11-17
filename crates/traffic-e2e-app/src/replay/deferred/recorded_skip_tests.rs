//! Private immutable-recording checks for engine preparation, without a Target.
use super::*;
use sha2::{Digest, Sha256};

#[tokio::test]
#[ignore = "requires the private completed recording named by TRAFFIC_E2E_SKIP_RECORDING"]
async fn recorded_skip_cases_prepare_with_large_attachments_and_rpc_evidence() {
    let root =
        PathBuf::from(std::env::var_os("TRAFFIC_E2E_SKIP_RECORDING").expect("recording root"));
    let temp = tempfile::tempdir().unwrap();
    let project_root = root
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == ".traffic-e2e"))
        .unwrap()
        .parent()
        .unwrap();
    let project = crate::AppConfig::load(project_root.join(".traffic-e2e/project.yaml")).unwrap();
    let policy = project_root.join(".traffic-e2e/policy.yaml");
    let mut selected = Vec::new();
    let mut inputs = Vec::new();
    for api in [
        "api-attachments-wildcard-download",
        "api-attachments-wildcard-executor-download",
        "api-devices-wildcard-commands",
        "api-devices-wildcard-upgrade",
        "api-plugins-installed-sync-device",
    ] {
        let mut cases = std::fs::read_dir(root.join("apis").join(api))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        cases.sort();
        for dir in cases {
            let path = dir.join("dependencies.jsonl");
            let bytes = std::fs::read(&path).unwrap();
            let large = bytes
                .split(|byte| *byte == b'\n')
                .any(|line| line.len() > 8 * 1024 * 1024);
            if api.starts_with("api-attachments-") && !large {
                continue;
            }
            if large {
                let target_root = root
                    .ancestors()
                    .find(|path| path.file_name().is_some_and(|name| name == ".traffic-e2e"))
                    .unwrap()
                    .parent()
                    .unwrap();
                crate::query_rewrite_case_dependencies(crate::RewriteCaseDependenciesOptions {
                    target_root: target_root.into(),
                    case_dir: dir.clone(),
                    target_id: None,
                })
                .unwrap();
                let mut observed = 0;
                crate::dependency_index::proof::visit(
                    &path,
                    |event| Ok(event["event_type"] == "http_exchange"),
                    |_| {
                        observed += 1;
                        Ok(())
                    },
                )
                .unwrap();
                assert!(observed > 0);
            }
            let id = dir.file_name().unwrap().to_str().unwrap().to_owned();
            inputs.push((path, format!("{:x}", Sha256::digest(&bytes))));
            selected.push((api, id));
        }
    }
    assert_eq!(selected.len(), 23);
    let config = ReplayConfig {
        case_dir: root,
        selected_case_ids: selected.iter().map(|(_, id)| id.clone()).collect(),
        dns_listen: "127.0.0.1:0".parse().unwrap(),
        tcp_listen: "127.0.0.1:0".parse().unwrap(),
        fake_cidr: "198.18.0.0/15".into(),
        report_path: Some(temp.path().join("report.json")),
        session_path: None,
        control_socket_path: None,
        ca_cert_path: None,
        ca_key_path: None,
        policy_path: Some(policy),
        http_ignore_query_params: vec![],
        process_owned_dependencies: project.process_owned_dependencies,
        allowed_unused_http: None,
    };
    let lifecycle = ReplayLifecycleConfig {
        dependency_loading: ReplayDependencyLoading {
            lazy_cases: true,
            cache_bytes: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let runtime = ReplayRuntime::load_with_lifecycle(
        config,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        lifecycle,
    )
    .await
    .unwrap();
    let mut failures = Vec::new();
    for (api, id) in selected {
        match prepare_case(runtime.state.clone(), &id).await {
            Ok(()) => println!("{api} {id}: engine preparation passed"),
            Err(error) => failures.push(format!("{api} {id}: {error:#}")),
        }
    }
    for (path, digest) in inputs {
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(path).unwrap())),
            digest
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
