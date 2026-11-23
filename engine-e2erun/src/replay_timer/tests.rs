use super::*;
use std::os::unix::net::UnixListener;

#[test]
fn stages_a_private_plan_and_shares_only_the_timer_socket_with_target() {
    let plan = br#"{"cases":{"case":[]}}"#;
    let staged = ManagedTimer::stage(plan).unwrap();
    let directory = staged.directory.clone();
    assert_eq!(
        staged.replay_args(),
        [
            std::ffi::OsStr::new("--timer-plan"),
            staged.plan.as_os_str(),
            std::ffi::OsStr::new("--timer-socket"),
            staged.socket.as_os_str(),
        ]
    );
    assert_eq!(fs::read(&staged.plan).unwrap(), plan);
    assert_eq!(
        fs::metadata(&directory).unwrap().mode() & 0o777,
        PRIVATE_DIR_MODE
    );
    assert_eq!(
        fs::metadata(&staged.plan).unwrap().mode() & 0o777,
        PRIVATE_FILE_MODE
    );
    let _listener = UnixListener::bind(&staged.socket).unwrap();
    fs::set_permissions(&staged.socket, Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
    let socket = staged.socket_for_target().unwrap();
    assert_eq!(socket, staged.socket);
    assert_eq!(
        fs::metadata(socket).unwrap().mode() & 0o777,
        MOUNTED_SOCKET_MODE
    );
    assert_eq!(
        fs::metadata(&directory).unwrap().mode() & 0o777,
        PRIVATE_DIR_MODE
    );
    drop(staged);
    assert!(!directory.exists());
}

#[test]
fn never_opens_a_socket_outside_a_private_directory() {
    let staged = ManagedTimer::stage(b"{}").unwrap();
    let _listener = UnixListener::bind(&staged.socket).unwrap();
    fs::set_permissions(&staged.socket, Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
    fs::set_permissions(&staged.directory, Permissions::from_mode(0o755)).unwrap();

    assert!(staged.socket_for_target().is_err());
    assert_eq!(
        fs::metadata(&staged.socket).unwrap().mode() & 0o777,
        PRIVATE_FILE_MODE
    );
}

#[test]
fn rejects_oversized_plan_files() {
    let oversized = tempfile::NamedTempFile::new().unwrap();
    oversized
        .as_file()
        .set_len(MAX_PLAN_BYTES as u64 + 1)
        .unwrap();
    assert!(
        read_plan_file(oversized.path())
            .unwrap_err()
            .to_string()
            .contains("too large")
    );
}
