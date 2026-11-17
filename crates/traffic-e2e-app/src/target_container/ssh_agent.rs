use std::fs;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};

const SOCKET_DIRECTORY: &str = ".traffic-e2e/local/socks";
const SOCKET_NAME: &str = "ssh-agent.sock";

pub(super) struct ManagedSshAgent {
    socket: PathBuf,
}

impl ManagedSshAgent {
    pub(super) fn prepare(target_root: &Path) -> Result<Self> {
        let socket_directory = target_root.join(SOCKET_DIRECTORY);
        prepare_socket_directory(&socket_directory)?;
        let socket = socket_directory.join(SOCKET_NAME);

        match inspect_agent(&socket)? {
            AgentState::Ready => return Ok(Self { socket }),
            AgentState::Empty => load_identities(&socket)?,
            AgentState::Unavailable => {
                remove_stale_socket(&socket)?;
                start_agent(&socket)?;
                load_identities(&socket)?;
            }
        }

        ensure!(
            inspect_agent(&socket)? == AgentState::Ready,
            "managed target-build SSH agent has no loaded identity after ssh-add"
        );
        Ok(Self { socket })
    }

    pub(super) fn apply_to(&self, command: &mut tokio::process::Command) {
        let mut forwarding = std::ffi::OsString::from("default=");
        forwarding.push(&self.socket);
        command.arg("--ssh").arg(forwarding);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentState {
    Ready,
    Empty,
    Unavailable,
}

fn prepare_socket_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "managed target-build SSH socket directory must be a directory and not a symlink: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)
            .with_context(|| {
                format!(
                    "failed to create managed target-build SSH socket directory {}",
                    path.display()
                )
            })?,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect managed target-build SSH socket directory {}",
                    path.display()
                )
            });
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to secure managed target-build SSH socket directory {}",
            path.display()
        )
    })?;
    Ok(())
}

fn inspect_agent(socket: &Path) -> Result<AgentState> {
    let metadata = match fs::metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AgentState::Unavailable);
        }
        Err(_) => return Ok(AgentState::Unavailable),
    };
    if !metadata.file_type().is_socket() {
        return Ok(AgentState::Unavailable);
    }

    let status = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to inspect managed target-build SSH identities with ssh-add -l")?;
    Ok(match status.code() {
        Some(0) => AgentState::Ready,
        Some(1) => AgentState::Empty,
        _ => AgentState::Unavailable,
    })
}

fn remove_stale_socket(socket: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect stale managed target-build SSH socket {}",
                    socket.display()
                )
            });
        }
    };
    ensure!(
        !metadata.is_dir(),
        "managed target-build SSH socket path is a directory: {}",
        socket.display()
    );
    fs::remove_file(socket).with_context(|| {
        format!(
            "failed to remove stale managed target-build SSH socket {}",
            socket.display()
        )
    })
}

fn start_agent(socket: &Path) -> Result<()> {
    let output = Command::new("ssh-agent")
        .arg("-a")
        .arg(socket)
        .arg("-s")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("failed to start managed target-build ssh-agent")?;
    if !output.status.success() && inspect_agent(socket)? == AgentState::Unavailable {
        bail!(
            "failed to start managed target-build ssh-agent: {}",
            bounded_command_error(&output.stderr)
        );
    }
    ensure!(
        matches!(
            inspect_agent(socket)?,
            AgentState::Ready | AgentState::Empty
        ),
        "managed target-build ssh-agent did not create a usable socket at {}",
        socket.display()
    );
    Ok(())
}

fn load_identities(socket: &Path) -> Result<()> {
    let output = Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", socket)
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("failed to load default identities into the managed target-build SSH agent")?;
    ensure!(
        output.status.success() && inspect_agent(socket)? == AgentState::Ready,
        "managed target-build SSH agent could not load a default identity with ssh-add: {}",
        bounded_command_error(&output.stderr)
    );
    Ok(())
}

fn bounded_command_error(bytes: &[u8]) -> String {
    const MAX_CHARS: usize = 512;
    let text = String::from_utf8_lossy(bytes).replace(['\r', '\n'], " ");
    let text = text.trim();
    let mut chars = text.chars();
    let bounded = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else if bounded.is_empty() {
        "command exited unsuccessfully without an error message".to_string()
    } else {
        bounded
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn managed_socket_is_repository_local() {
        let root = Path::new("/target/service");
        assert_eq!(
            root.join(SOCKET_DIRECTORY).join(SOCKET_NAME),
            Path::new("/target/service/.traffic-e2e/local/socks/ssh-agent.sock")
        );
    }

    #[test]
    fn command_errors_are_one_line_and_bounded() {
        let error = bounded_command_error(format!("first\n{}", "x".repeat(600)).as_bytes());
        assert!(!error.contains('\n'));
        assert!(error.chars().count() <= 513);
        assert!(error.ends_with('…'));
    }

    #[test]
    fn socket_directory_is_private_and_rejects_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("socks");
        prepare_socket_directory(&directory).unwrap();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let linked = temporary.path().join("linked-socks");
        symlink(&directory, &linked).unwrap();
        assert!(prepare_socket_directory(&linked).is_err());
    }

    #[test]
    fn stale_socket_path_is_removed() {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join(SOCKET_NAME);
        fs::write(&socket, b"stale").unwrap();
        remove_stale_socket(&socket).unwrap();
        assert!(!socket.exists());
    }
}
