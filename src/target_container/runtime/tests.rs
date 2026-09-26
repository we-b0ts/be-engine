use super::*;

#[test]
fn runtime_names_are_docker_safe() {
    let name = runtime_name(
        Path::new("/tmp/service graph"),
        "record-comparison",
        "20260806000000",
        "target",
    )
    .unwrap();
    assert_eq!(
        name,
        "traffic-e2e-service-graph-record-comparison-20260806000000-target"
    );
}

#[test]
fn bind_mounts_reject_docker_mount_delimiters() {
    assert!(bind_mount(Path::new("/tmp/with,comma"), "/data1/weibo/confs", false).is_err());
    assert_eq!(
        bind_mount(Path::new("/tmp/config"), "/data1/weibo/confs", false).unwrap(),
        "type=bind,source=/tmp/config,target=/data1/weibo/confs,readonly"
    );
    assert_eq!(
        bind_mount(Path::new("/tmp/config"), "/data1/weibo/confs", true).unwrap(),
        "type=bind,source=/tmp/config,target=/data1/weibo/confs"
    );
}

#[test]
fn target_log_bound_keeps_the_latest_output() {
    let mut log = vec![b'a'; MAX_TARGET_LOG_BYTES];
    log.extend_from_slice(b"latest failure\n");

    let bounded = bounded_log(log);
    let text = String::from_utf8(bounded).unwrap();

    assert!(text.starts_with("[traffic-e2e omitted "));
    assert!(text.ends_with("latest failure\n"));
}
