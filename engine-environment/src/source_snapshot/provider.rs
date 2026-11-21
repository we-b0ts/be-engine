use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::CapturedSource;

#[derive(Debug, Clone)]
pub struct KubernetesSourceOptions {
    pub pod: String,
    pub namespace: String,
    pub container: Option<String>,
    pub kubeconfig: Option<PathBuf>,
    pub context: Option<String>,
    pub kubectl_binary: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ContainerSourceOptions {
    pub container: String,
}

#[derive(Debug, Clone)]
pub enum SourceOptions {
    Kubernetes(KubernetesSourceOptions),
    Container(ContainerSourceOptions),
}

impl SourceOptions {
    pub(super) fn capture(&self, mounts_root: &Path) -> Result<CapturedSource> {
        match self {
            Self::Kubernetes(options) => super::kubernetes::capture(options, mounts_root),
            Self::Container(options) => super::container::capture(options, mounts_root),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum SourceProviderEvidence {
    #[serde(rename = "kubernetes_pod")]
    KubernetesPod {
        context: Option<String>,
        namespace: String,
        pod: String,
        pod_uid: String,
        container: String,
        restart_count: u32,
    },
    #[serde(rename = "docker_container")]
    DockerContainer {
        container: String,
        container_id: String,
        source_image_id: String,
        restart_count: u32,
    },
}

impl SourceProviderEvidence {
    pub(super) fn matches(&self, options: &SourceOptions) -> bool {
        match (self, options) {
            (
                Self::KubernetesPod {
                    context,
                    namespace,
                    pod,
                    container,
                    ..
                },
                SourceOptions::Kubernetes(options),
            ) => {
                namespace == &options.namespace
                    && pod == &options.pod
                    && options
                        .container
                        .as_ref()
                        .is_none_or(|requested| requested == container)
                    && options
                        .context
                        .as_ref()
                        .is_none_or(|requested| Some(requested) == context.as_ref())
            }
            (
                Self::DockerContainer {
                    container,
                    container_id,
                    ..
                },
                SourceOptions::Container(options),
            ) => {
                let requested = options
                    .container
                    .strip_prefix('/')
                    .unwrap_or(&options.container);
                requested == container
                    || (requested.len() >= 12 && container_id.starts_with(requested))
            }
            _ => false,
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::KubernetesPod {
                namespace,
                pod,
                pod_uid,
                container,
                ..
            } => {
                !namespace.is_empty()
                    && !pod.is_empty()
                    && !pod_uid.is_empty()
                    && !container.is_empty()
            }
            Self::DockerContainer {
                container,
                container_id,
                source_image_id,
                ..
            } => {
                !container.is_empty()
                    && container_id.len() == 64
                    && container_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && super::image::is_image_id(source_image_id)
            }
        };
        ensure!(valid, "source snapshot provider evidence is invalid");
        Ok(())
    }
}
