use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

pub(crate) const SOCKS_DIR: &str = "/data1/breeze/socks";
const MAX_DESCRIPTOR_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) identity: String,
    pub(crate) namespace: String,
    pub(crate) socket_type: String,
    pub(crate) port: u16,
}

impl Descriptor {
    fn parse(path: PathBuf) -> Result<Option<Self>> {
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .context("Breeze descriptor filename is not valid UTF-8")?;
        if filename == "breeze_sdk.lock" || filename.ends_with(".sock") {
            return Ok(None);
        }

        let fields = filename.split('@').collect::<Vec<_>>();
        ensure!(
            fields.len() == 3,
            "Breeze descriptor {filename:?} must contain exactly three @-separated fields"
        );
        let service = fields[0];
        let (socket_type, port) = fields[1].rsplit_once(':').with_context(|| {
            format!("Breeze descriptor {filename:?} is missing its socket port")
        })?;
        ensure!(
            !socket_type.is_empty(),
            "Breeze descriptor {filename:?} has an empty socket type"
        );
        let port = port
            .parse::<u16>()
            .with_context(|| format!("Breeze descriptor {filename:?} has an invalid TCP port"))?;
        ensure!(
            port != 0,
            "Breeze descriptor {filename:?} has an out-of-range TCP port"
        );
        let protocol = fields[2];
        ensure!(
            !protocol.is_empty(),
            "Breeze descriptor {filename:?} has an empty protocol"
        );
        let namespace = parse_namespace(service)
            .with_context(|| format!("Breeze descriptor {filename:?} has an invalid identity"))?;

        Ok(Some(Self {
            identity: format!("{service}@{socket_type}@{protocol}"),
            namespace,
            socket_type: socket_type.to_string(),
            port,
        }))
    }
}

pub(crate) fn resolve_business_resource(
    directory: &Path,
    namespace: &str,
    socket_type: &str,
) -> Result<Descriptor> {
    validate_selector("Breeze business resource", namespace)?;
    validate_selector("Breeze socket type", socket_type)?;
    resolve(
        directory,
        |descriptor| {
            descriptor.namespace == namespace && descriptor.socket_type == socket_type
        },
        |filename| filename.contains(namespace),
    )
    .with_context(|| {
        format!(
            "failed to resolve Breeze business resource {namespace:?} with socket type {socket_type:?}"
        )
    })
}

pub(crate) fn resolve_identity(directory: &Path, identity: &str) -> Result<Descriptor> {
    validate_selector("Breeze resource identity", identity)?;
    ensure!(
        identity.split('@').count() == 3,
        "Breeze resource identity must be the stable service@socket-type@protocol identity"
    );
    let service = identity.split('@').next().expect("validated identity");
    resolve(
        directory,
        |descriptor| descriptor.identity == identity,
        |filename| filename.starts_with(service),
    )
    .with_context(|| format!("failed to resolve Breeze resource identity {identity:?}"))
}

fn resolve(
    directory: &Path,
    matches: impl Fn(&Descriptor) -> bool,
    claims_resource: impl Fn(&str) -> bool,
) -> Result<Descriptor> {
    let mut paths = fs::read_dir(directory)
        .with_context(|| {
            format!(
                "failed to read Breeze descriptor directory {}",
                directory.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| {
            format!(
                "failed to enumerate Breeze descriptor directory {}",
                directory.display()
            )
        })?;
    ensure!(
        paths.len() <= MAX_DESCRIPTOR_ENTRIES,
        "Breeze descriptor directory {} exceeds the {} entry safety limit",
        directory.display(),
        MAX_DESCRIPTOR_ENTRIES
    );
    paths.sort();

    let mut candidates = Vec::new();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_string();
        let descriptor = match Descriptor::parse(path) {
            Ok(descriptor) => descriptor,
            Err(error) if claims_resource(&filename) => return Err(error),
            Err(_) => continue,
        };
        if descriptor.as_ref().is_some_and(&matches) {
            candidates.push(descriptor.expect("checked descriptor"));
        }
    }
    match candidates.len() {
        1 => Ok(candidates.pop().expect("one Breeze descriptor")),
        0 => bail!(
            "no compatible Breeze descriptor exists in {}; replay-safe resolution never creates one",
            directory.display()
        ),
        count => bail!(
            "{count} compatible Breeze descriptors exist in {}; full resource identity is ambiguous",
            directory.display()
        ),
    }
}

fn parse_namespace(service: &str) -> Result<String> {
    let parts = service.split('+').collect::<Vec<_>>();
    ensure!(
        parts.len() >= 6 && parts[1] == "3" && parts[2] == "config",
        "unsupported Breeze service identity"
    );
    match parts[3] {
        "v1" => {
            ensure!(parts.len() == 6, "invalid Breeze v1 service identity");
            let namespace = parts[5]
                .strip_prefix("all:")
                .context("Breeze v1 namespace must start with all:")?;
            validate_selector("Breeze namespace", namespace)?;
            Ok(namespace.to_string())
        }
        "cloud" => {
            ensure!(parts.len() == 7, "invalid Breeze cloud service identity");
            let namespace = parts[6]
                .split_once('#')
                .map_or(parts[6], |(namespace, _)| namespace);
            validate_selector("Breeze namespace", namespace)?;
            Ok(namespace.to_string())
        }
        version => bail!("unsupported Breeze descriptor version {version:?}"),
    }
}

fn validate_selector(label: &str, value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{label} must not be empty");
    ensure!(
        value == value.trim() && !value.contains(['\r', '\n']),
        "{label} must be a single line without surrounding whitespace"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(directory: &Path, filename: &str) {
        std::fs::write(directory.join(filename), "").unwrap();
    }

    #[test]
    fn resolves_business_resource_to_stable_identity_and_current_port() {
        let temp = tempfile::tempdir().unwrap();
        descriptor(temp.path(), "breeze_sdk.lock");
        descriptor(
            temp.path(),
            "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs",
        );
        descriptor(
            temp.path(),
            "static.config.api.demo.test+3+config+cloud+redis+user+other@redis:9301@rs",
        );

        let resolved = resolve_business_resource(temp.path(), "user-video", "mc").unwrap();

        assert_eq!(
            resolved.identity,
            "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc@cs"
        );
        assert_eq!(resolved.namespace, "user-video");
        assert_eq!(resolved.port, 9448);
    }

    #[test]
    fn exact_identity_reuses_port_and_rejects_missing_or_duplicate_descriptors() {
        let temp = tempfile::tempdir().unwrap();
        let identity = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc@cs";
        descriptor(
            temp.path(),
            "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs",
        );
        assert_eq!(resolve_identity(temp.path(), identity).unwrap().port, 9448);

        descriptor(
            temp.path(),
            "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9449@cs",
        );
        assert!(resolve_identity(temp.path(), identity).is_err());
        assert!(
            resolve_identity(
                temp.path(),
                "config.api.demo.test+3+config+v1+cache.pool+all:missing@mc@cs"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_malformed_descriptor_instead_of_using_directory_order() {
        let temp = tempfile::tempdir().unwrap();
        descriptor(
            temp.path(),
            "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:not-a-port@cs",
        );
        descriptor(
            temp.path(),
            "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs",
        );

        assert!(resolve_business_resource(temp.path(), "user-video", "mc").is_err());
    }
}
