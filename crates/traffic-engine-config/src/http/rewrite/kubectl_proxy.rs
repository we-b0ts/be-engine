use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep, timeout};
use tracing::info;
use uuid::Uuid;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Default)]
pub struct KubectlProxyManager {
    inner: Arc<Mutex<Option<ManagedProxy>>>,
}

pub(super) struct KubectlProxySpec {
    pub(super) binary: String,
    pub(super) listen: SocketAddr,
    pub(super) kubeconfig: Vec<u8>,
}

struct ManagedProxy {
    binary: String,
    listen: SocketAddr,
    kubeconfig: Vec<u8>,
    kubeconfig_path: PathBuf,
    child: Child,
}

impl KubectlProxyManager {
    pub(super) async fn ensure_running(&self, spec: KubectlProxySpec) -> Result<()> {
        let mut managed = self.inner.lock().await;
        if let Some(current) = managed.as_mut() {
            if current.matches(&spec) && current.is_running()? {
                return Ok(());
            }
            current.stop().await;
            *managed = None;
        }

        if port_is_open(spec.listen).await {
            bail!(
                "kubectl proxy listen address {} is already in use by an unmanaged process",
                spec.listen
            );
        }

        let kubeconfig_path = write_kubeconfig(&spec.kubeconfig).await?;
        let child = match spawn_kubectl_proxy(&spec, &kubeconfig_path) {
            Ok(child) => child,
            Err(error) => {
                remove_file(&kubeconfig_path);
                return Err(error);
            }
        };
        let mut current = ManagedProxy {
            binary: spec.binary,
            listen: spec.listen,
            kubeconfig: spec.kubeconfig,
            kubeconfig_path,
            child,
        };
        if let Err(error) = current.wait_ready().await {
            current.stop().await;
            return Err(error);
        }
        info!(listen = %current.listen, "managed kubectl proxy is ready");
        *managed = Some(current);
        Ok(())
    }

    pub async fn shutdown(&self) {
        let current = self.inner.lock().await.take();
        if let Some(mut current) = current {
            current.stop().await;
        }
    }
}

impl ManagedProxy {
    fn matches(&self, spec: &KubectlProxySpec) -> bool {
        self.binary == spec.binary
            && self.listen == spec.listen
            && self.kubeconfig == spec.kubeconfig
    }

    fn is_running(&mut self) -> Result<bool> {
        Ok(self
            .child
            .try_wait()
            .context("failed to inspect managed kubectl proxy")?
            .is_none())
    }

    async fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .context("failed to inspect managed kubectl proxy during startup")?
            {
                bail!("managed kubectl proxy exited before readiness with status {status}");
            }
            if TcpStream::connect(self.listen).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "managed kubectl proxy did not listen on {} within {} seconds",
                    self.listen,
                    STARTUP_TIMEOUT.as_secs()
                );
            }
            sleep(READINESS_INTERVAL).await;
        }
    }

    async fn stop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.start_kill();
            let _ = self.child.wait().await;
        }
        remove_file(&self.kubeconfig_path);
    }
}

impl Drop for ManagedProxy {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        remove_file(&self.kubeconfig_path);
    }
}

fn spawn_kubectl_proxy(spec: &KubectlProxySpec, kubeconfig_path: &Path) -> Result<Child> {
    let mut command = Command::new(&spec.binary);
    command
        .arg("--kubeconfig")
        .arg(kubeconfig_path)
        .arg("proxy")
        .arg("--address")
        .arg(spec.listen.ip().to_string())
        .arg("--port")
        .arg(spec.listen.port().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
        .spawn()
        .with_context(|| format!("failed to start kubectl binary {:?}", spec.binary))
}

async fn write_kubeconfig(kubeconfig: &[u8]) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "traffic-e2e-kubeconfig-{}-{}.yaml",
        std::process::id(),
        Uuid::new_v4()
    ));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(&path)
        .await
        .with_context(|| format!("failed to create private kubeconfig {}", path.display()))?;
    if let Err(error) = file.write_all(kubeconfig).await {
        remove_file(&path);
        return Err(error).context("failed to write private kubectl proxy kubeconfig");
    }
    if let Err(error) = file.flush().await {
        remove_file(&path);
        return Err(error).context("failed to flush private kubectl proxy kubeconfig");
    }
    Ok(path)
}

async fn port_is_open(listen: SocketAddr) -> bool {
    timeout(Duration::from_millis(200), TcpStream::connect(listen))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn remove_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn writes_kubeconfig_with_owner_only_permissions() {
        let path = write_kubeconfig(b"apiVersion: v1\n").await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        remove_file(&path);
    }

    #[tokio::test]
    async fn refuses_to_replace_process_already_using_listen_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let manager = KubectlProxyManager::default();
        let error = manager
            .ensure_running(KubectlProxySpec {
                binary: "missing-kubectl-binary".to_string(),
                listen: listener.local_addr().unwrap(),
                kubeconfig: b"secret".to_vec(),
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("already in use"));
    }
}
