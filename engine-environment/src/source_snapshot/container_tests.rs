use super::*;

#[test]
fn commit_output_accepts_docker_deprecation_notices() {
    let id = format!("sha256:{}", "a".repeat(64));
    assert_eq!(
        committed_image_id(format!("{id}\n").as_bytes()).unwrap(),
        id
    );
    assert_eq!(
        committed_image_id(format!("Flag --pause has been deprecated\n{id}\n").as_bytes()).unwrap(),
        id
    );
    assert!(committed_image_id(b"invalid image\n").is_err());
}

fn inspection(status: &str) -> ContainerInspection {
    serde_json::from_value(serde_json::json!({
        "Id": "a".repeat(64), "Name": "/source", "Image": format!("sha256:{}", "b".repeat(64)),
        "RestartCount": 0,
        "State": { "Status": status, "Running": status == "running", "Paused": false,
            "Restarting": false, "Dead": false, "StartedAt": "start", "FinishedAt": "finish" },
        "Config": { "Image": "local:latest", "Env": ["APP_TOKEN=a=b", "PATH=/bin", "MULTILINE=a\nb"],
            "Entrypoint": [], "Cmd": ["/bin/sh", "-c", "sleep 3600"], "WorkingDir": "/app", "User": "998:998" },
        "HostConfig": { "Privileged": false, "ReadonlyRootfs": true, "CapAdd": ["NET_BIND_SERVICE"],
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"] },
        "Mounts": []
    })).unwrap()
}

#[test]
fn stopped_and_running_containers_share_the_configured_launch_contract() {
    for state in ["running", "exited", "created"] {
        let container = inspection(state);
        validate_container(&container).unwrap();
        let environment = environment(&container.config).unwrap();
        assert_eq!(environment["APP_TOKEN"], "a=b");
        assert_eq!(environment["MULTILINE"], "a\nb");
        let security = security(&container.host_config).unwrap();
        assert!(security.read_only_root_filesystem && security.no_new_privileges);
        assert_eq!(security.capability_drop, ["ALL"]);
    }
    for state in ["paused", "restarting", "dead", "removing"] {
        assert!(validate_container(&inspection(state)).is_err());
    }
}

#[test]
fn rejects_duplicate_environment_and_unsupported_security_options() {
    let mut container = inspection("exited");
    container
        .config
        .env
        .as_mut()
        .unwrap()
        .push("APP_TOKEN=other".into());
    assert!(environment(&container.config).is_err());
    container.host_config.security_opt = Some(vec!["seccomp=custom.json".into()]);
    assert!(security(&container.host_config).is_err());
}

#[test]
fn rejects_overlapping_mounts_before_copying() {
    let mounts = vec![
        Mount {
            kind: "bind".into(),
            source: Some("/config".into()),
            destination: "/app".into(),
            writable: false,
        },
        Mount {
            kind: "volume".into(),
            source: None,
            destination: "/app/data".into(),
            writable: true,
        },
    ];
    assert!(validate_mounts(&mounts).is_err());
}

#[test]
fn provider_evidence_is_typed_and_preserves_kubernetes_serialization() {
    let pod = r#"{"kind":"kubernetes_pod","context":null,"namespace":"default","pod":"source","pod_uid":"uid","container":"app","restart_count":0}"#;
    let evidence: SourceProviderEvidence = serde_json::from_str(pod).unwrap();
    assert_eq!(serde_json::to_string(&evidence).unwrap(), pod);
    assert!(serde_json::from_str::<SourceProviderEvidence>(r#"{"kind":"unknown"}"#).is_err());
    let local = SourceProviderEvidence::DockerContainer {
        container: "local".into(),
        container_id: "a".repeat(64),
        source_image_id: format!("sha256:{}", "b".repeat(64)),
        restart_count: 0,
    };
    local.validate().unwrap();
    assert!(local.matches(&super::super::SourceOptions::Container(
        ContainerSourceOptions {
            container: "local".into()
        }
    )));
    assert!(!local.matches(&super::super::SourceOptions::Container(
        ContainerSourceOptions {
            container: "other".into()
        }
    )));
    let serialized = serde_json::to_value(&local).unwrap();
    assert!(serialized.get("pod").is_none());
}

struct DockerFixture {
    containers: Vec<String>,
    images: Vec<String>,
    volumes: Vec<String>,
}

impl Drop for DockerFixture {
    fn drop(&mut self) {
        for container in &self.containers {
            let _ = docker(
                &["rm", "--force", "--volumes", container],
                "remove test container",
            );
        }
        for image in &self.images {
            let _ = docker(&["image", "rm", image], "remove test image");
        }
        for volume in &self.volumes {
            let _ = docker(&["volume", "rm", volume], "remove test volume");
        }
    }
}

// This exercises the real Docker archive API for mounted paths on stopped
// containers as well as commit, image save/load, and source-independent reuse.
#[test]
#[ignore = "requires Docker and TRAFFIC_E2E_TEST_CONTAINER_IMAGE with /bin/sh, sleep, and cat (linux/amd64)"]
fn docker_provider_initializes_running_and_stopped_containers() {
    use super::super::{
        SourceOptions, capture_source_snapshot, copy_path, load, write_runtime_projection,
    };
    let base = std::env::var("TRAFFIC_E2E_TEST_CONTAINER_IMAGE")
        .expect("set TRAFFIC_E2E_TEST_CONTAINER_IMAGE");
    let mut fixture = DockerFixture {
        containers: vec![],
        images: vec![],
        volumes: vec![],
    };
    for state in ["running", "exited", "created"] {
        let temp = tempfile::tempdir().unwrap();
        let bind = temp.path().join("input");
        fs::create_dir(&bind).unwrap();
        fs::write(bind.join("config"), "captured bind").unwrap();
        let volume = format!(
            "traffic-e2e-provider-test-{}",
            uuid::Uuid::new_v4().simple()
        );
        docker(&["volume", "create", &volume], "create test volume").unwrap();
        fixture.volumes.push(volume.clone());
        let name = format!(
            "traffic-e2e-provider-test-{}",
            uuid::Uuid::new_v4().simple()
        );
        let mounted = format!("{}:/input:ro", bind.display());
        let volume_mount = format!("{volume}:/data");
        docker(
            &[
                "create",
                "--name",
                &name,
                "--user",
                "0:0",
                "--workdir",
                "/tmp",
                "--env",
                "APP_CONFIG=container override",
                "--volume",
                &mounted,
                "--volume",
                &volume_mount,
                "--entrypoint",
                "",
                &base,
                "/bin/sh",
                "-c",
                "sleep 3600",
            ],
            "create test source",
        )
        .unwrap();
        fixture.containers.push(name.clone());
        let changed = temp.path().join("changed");
        fs::write(&changed, "writable layer").unwrap();
        docker(
            &["cp", changed.to_str().unwrap(), &format!("{name}:/changed")],
            "modify test writable layer",
        )
        .unwrap();
        docker(
            &[
                "cp",
                changed.to_str().unwrap(),
                &format!("{name}:/data/seed"),
            ],
            "seed test volume",
        )
        .unwrap();
        if state != "created" {
            docker(&["start", &name], "start test source").unwrap();
        }
        if state == "exited" {
            docker(&["stop", "--time", "0", &name], "stop test source").unwrap();
        }
        let before = inspect_container(&name).unwrap();
        let options = SourceOptions::Container(ContainerSourceOptions {
            container: name.clone(),
        });
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "input/config", "changed"],
            vec![
                "-c",
                "user.name=Provider Test",
                "-c",
                "user.email=provider@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        ] {
            let status = Command::new("git")
                .args(args)
                .current_dir(temp.path())
                .status()
                .unwrap();
            assert!(status.success());
        }
        let initialized = crate::initialize_repository_config(crate::RepositoryConfigInitOptions {
            target_root: temp.path().to_path_buf(),
            source: traffic_engine::SourceOptions::Container(
                traffic_engine::ContainerSourceOptions {
                    container: name.clone(),
                },
            ),
            http_backend_port: crate::DEFAULT_HTTP_BACKEND_PORT,
            http_gateway_port: crate::DEFAULT_HTTP_GATEWAY_PORT,
            readiness_path: "/healthz".into(),
            upstream_dns: "10.10.10.11:53".parse().unwrap(),
            env_file: None,
        })
        .unwrap();
        assert!(temp.path().join(".traffic-e2e/project.yaml").is_file());
        assert!(temp.path().join(".traffic-e2e/Dockerfile.source").is_file());
        let report = initialized.source_snapshot;
        fixture.images.push(report.image.local_id.clone());
        assert_eq!(report.status, "captured");
        assert_eq!(before, inspect_container(&name).unwrap());
        let snapshot = load(temp.path()).unwrap();
        assert_eq!(
            snapshot.runtime.environment["APP_CONFIG"],
            "container override"
        );
        assert_eq!(snapshot.runtime.working_directory.as_deref(), Some("/tmp"));
        assert!(snapshot.runtime.image_entrypoint.is_empty());
        assert_eq!(
            snapshot.runtime.image_command,
            ["/bin/sh", "-c", "sleep 3600"]
        );
        assert!(
            snapshot
                .manifest
                .mounts
                .iter()
                .any(|mount| mount.path == Path::new("/data") && mount.writable)
        );
        docker(&["rm", "--force", &name], "remove original test source").unwrap();
        let reused = capture_source_snapshot(temp.path(), &options).unwrap();
        assert_eq!(reused.status, "existing");
        fs::write(bind.join("config"), "modified after init").unwrap();
        for (source, expected) in [
            ("/changed", "writable layer"),
            ("/input/config", "captured bind"),
            ("/data/seed", "writable layer"),
        ] {
            let destination = temp
                .path()
                .join(format!("copy-{}", source.replace('/', "_")));
            copy_path(temp.path(), Path::new(source), &destination).unwrap();
            assert_eq!(fs::read_to_string(destination).unwrap(), expected);
        }
        // Local-only snapshot images remain recoverable after Docker cleanup.
        docker(
            &["image", "rm", &report.image.local_id],
            "remove test snapshot image",
        )
        .unwrap();
        write_runtime_projection(&temp.path().join("projection.json"), temp.path()).unwrap();
        assert_eq!(
            inspect_image(&report.image.local_id).unwrap().id,
            report.image.local_id
        );
        let projected = docker(
            &[
                "run",
                "--rm",
                "--entrypoint",
                "/bin/sh",
                &report.image.local_id,
                "-c",
                "printf '%s:%s:' \"$APP_CONFIG\" \"$PWD\"; cat /changed",
            ],
            "verify captured launch configuration",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(projected.stdout).unwrap(),
            "container override:/tmp:writable layer"
        );
        if state == "created" {
            docker(
                &["image", "rm", &report.image.local_id],
                "remove test snapshot image",
            )
            .unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(
                    temp.path()
                        .join(crate::repository::LOCAL_SOURCE_ROOT)
                        .join("image.tar"),
                )
                .unwrap()
                .set_len(0)
                .unwrap();
            let error = write_runtime_projection(&temp.path().join("corrupt.json"), temp.path())
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("source image archive content changed")
            );
        }
    }
}
