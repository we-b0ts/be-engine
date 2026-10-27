//! Scoped kubectl children and bounded pipe handling; never owns Source requests.

use std::{
    net::SocketAddr,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::{Child, Command},
    sync::watch,
};

use super::diagnostics::ForwardDiagnostics;
use crate::config::KubernetesConfig;

const LINE_LIMIT: usize = 4096;
const OUTPUT_LIMIT: u64 = 1024 * 1024;
const STDERR_LIMIT: u64 = 16 * 1024;
const EXIT_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(100);

pub(super) struct KubectlChild {
    child: Child,
    group: Option<u32>,
}

impl KubectlChild {
    pub(super) fn spawn(
        config: &KubernetesConfig,
        namespace: &str,
        args: &[String],
    ) -> Result<Self> {
        let mut command = Command::new(&config.kubectl_binary);
        if let Some(path) = &config.kubeconfig {
            command.arg("--kubeconfig").arg(path);
        }
        if let Some(context) = &config.context {
            command.arg("--context").arg(context);
        }
        command
            .arg("--namespace")
            .arg(namespace)
            .args(args)
            .env("LC_ALL", "C")
            .env_remove(crate::request_headers::ENCRYPTION_KEY_ENV)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command.process_group(0);
        let child = command
            .spawn()
            .context("failed to start kubectl; install it in the recording image")?;
        let group = child.id();
        Ok(Self { child, group })
    }

    pub(super) async fn output(&mut self) -> Result<Vec<u8>> {
        let stdout = self.child.stdout.take().context("missing kubectl stdout")?;
        let stderr = self.child.stderr.take().context("missing kubectl stderr")?;
        let read_stdout = bounded_output(stdout, OUTPUT_LIMIT);
        let read_stderr = bounded_output(stderr, STDERR_LIMIT);
        let (stdout, _stderr, status) = tokio::try_join!(read_stdout, read_stderr, async {
            self.child
                .wait()
                .await
                .context("failed waiting for kubectl")
        })?;
        ensure!(
            status.success(),
            "kubectl Service discovery failed ({status}); check kubeconfig, context and Service/Pod permissions"
        );
        Ok(stdout)
    }

    pub(super) async fn forward(
        mut self,
        identity: String,
        mut on_ready: impl FnMut(SocketAddr) -> Result<()>,
        mut stopped: watch::Receiver<bool>,
        readiness_timeout: Duration,
    ) -> Result<()> {
        let stdout = self.child.stdout.take().context("missing kubectl stdout")?;
        let stderr = self.child.stderr.take().context("missing kubectl stderr")?;
        let mut stdout = Lines::new(stdout);
        let mut stderr = Lines::new(stderr);
        let mut ready = false;
        let ready_deadline = tokio::time::Instant::now() + readiness_timeout;
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut diagnostics = ForwardDiagnostics::new(self.child.id());
        loop {
            tokio::select! {
                biased;
                _ = stopped.changed() => {
                    if let Some(status) = self.child.try_wait().context("failed inspecting kubectl")? {
                        drain_output(&mut stdout, stdout_open, &mut stderr, stderr_open, &mut diagnostics).await;
                        diagnostics.emit_exit(&identity, &status, true);
                        return Ok(());
                    }
                    let status = self.stop().await?;
                    drain_output(&mut stdout, stdout_open, &mut stderr, stderr_open, &mut diagnostics).await;
                    diagnostics.emit_exit(&identity, &status, true);
                    return Ok(());
                },
                status = self.child.wait() => {
                    let status = status.context("failed waiting for kubectl")?;
                    drain_output(&mut stdout, stdout_open, &mut stderr, stderr_open, &mut diagnostics).await;
                    diagnostics.emit_exit(&identity, &status, false);
                    bail!("kubectl port-forward for {identity} exited ({status}); {}", diagnostics.summary());
                }
                _ = tokio::time::sleep_until(ready_deadline), if !ready => {
                    let status = self.stop().await?;
                    drain_output(&mut stdout, stdout_open, &mut stderr, stderr_open, &mut diagnostics).await;
                    diagnostics.emit_exit(&identity, &status, false);
                    bail!("kubectl port-forward readiness timed out for {identity}; {}", diagnostics.summary());
                }
                line = stdout.next(), if stdout_open => {
                    match line? {
                        Some(line) => {
                            diagnostics.stdout(&line);
                            if let Some(address) = ready_address(&line)? {
                                ensure!(!ready, "kubectl reported duplicate listeners for {identity}");
                                diagnostics.ready(address);
                                on_ready(address)?;
                                ready = true;
                            }
                        }
                        None => stdout_open = false,
                    }
                }
                line = stderr.next(), if stderr_open => {
                    match line? {
                        Some(line) => diagnostics.stderr(&line),
                        None => stderr_open = false,
                    }
                }
            }
        }
    }

    async fn stop(&mut self) -> Result<ExitStatus> {
        self.signal(libc::SIGTERM);
        let status = match tokio::time::timeout(Duration::from_secs(3), self.child.wait()).await {
            Ok(status) => status.context("failed reaping kubectl")?,
            Err(_) => {
                self.signal(libc::SIGKILL);
                self.child.wait().await.context("failed reaping kubectl")?
            }
        };
        // Authentication plugins can outlive the direct child. Keep them scoped too.
        self.signal(libc::SIGKILL);
        self.group = None;
        Ok(status)
    }

    fn signal(&self, signal: libc::c_int) {
        if let Some(group) = self.group {
            // The child owns this process group; never signal the controller's group.
            unsafe {
                libc::kill(-(group as libc::pid_t), signal);
            }
        }
    }
}

async fn drain_output(
    stdout: &mut Lines<impl AsyncRead + Unpin>,
    mut stdout_open: bool,
    stderr: &mut Lines<impl AsyncRead + Unpin>,
    mut stderr_open: bool,
    diagnostics: &mut ForwardDiagnostics,
) {
    // A child can exit before its final output wins the supervisor select.
    // Descendant auth plugins can retain the pipe; never let diagnostics delay
    // failure handling indefinitely or replace the original exit status.
    let mut stderr_drained = !stderr_open;
    let _ = tokio::time::timeout(EXIT_OUTPUT_DRAIN_TIMEOUT, async {
        while stdout_open || stderr_open {
            tokio::select! {
                line = stdout.next(), if stdout_open => {
                    match line {
                        Ok(Some(line)) => diagnostics.stdout(&line),
                        _ => stdout_open = false,
                    }
                }
                line = stderr.next(), if stderr_open => {
                    match line {
                        Ok(Some(line)) => diagnostics.stderr(&line),
                        Ok(None) => {
                            stderr_open = false;
                            stderr_drained = true;
                        }
                        Err(_) => stderr_open = false,
                    }
                }
            }
        }
    })
    .await;
    diagnostics.stderr_drained(stderr_drained);
}

impl Drop for KubectlChild {
    fn drop(&mut self) {
        self.signal(libc::SIGKILL);
    }
}

async fn bounded_output(reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() as u64 <= limit,
        "kubectl output exceeded its bounded capture limit"
    );
    Ok(bytes)
}

struct Lines<R> {
    reader: BufReader<R>,
    buffer: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Lines<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            buffer: Vec::new(),
        }
    }

    async fn next(&mut self) -> Result<Option<String>> {
        let remaining = LINE_LIMIT + 1 - self.buffer.len();
        let read = (&mut self.reader)
            .take(remaining as u64)
            .read_until(b'\n', &mut self.buffer)
            .await?;
        ensure!(
            self.buffer.len() <= LINE_LIMIT,
            "kubectl output line exceeded its bounded capture limit"
        );
        if read == 0 && self.buffer.is_empty() {
            return Ok(None);
        }
        let bytes = std::mem::take(&mut self.buffer);
        Ok(Some(
            String::from_utf8(bytes).context("kubectl output was not UTF-8")?,
        ))
    }
}

fn ready_address(line: &str) -> Result<Option<SocketAddr>> {
    let Some(rest) = line.trim().strip_prefix("Forwarding from ") else {
        return Ok(None);
    };
    let (address, target) = rest
        .split_once(" -> ")
        .ok_or_else(|| anyhow!("invalid kubectl forwarding notification"))?;
    let address: SocketAddr = address
        .parse()
        .context("invalid kubectl forwarding address")?;
    let target: u16 = target
        .parse()
        .context("invalid kubectl forwarding target port")?;
    ensure!(
        address.ip() == std::net::Ipv4Addr::LOCALHOST && address.port() != 0 && target != 0,
        "kubectl forwarding listener must use an allocated IPv4 loopback port"
    );
    Ok(Some(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_keep_service_and_pod_ports_independent() {
        assert_eq!(
            ready_address("Forwarding from 127.0.0.1:43210 -> 9000\n").unwrap(),
            Some("127.0.0.1:43210".parse().unwrap())
        );
        assert!(
            ready_address("Handling connection for 43210\n")
                .unwrap()
                .is_none()
        );
        for line in [
            "Forwarding from 0.0.0.0:43210 -> 9000",
            "Forwarding from 127.0.0.1:0 -> 9000",
            "Forwarding from localhost:1 -> 9000",
        ] {
            assert!(ready_address(line).is_err());
        }
    }
}
