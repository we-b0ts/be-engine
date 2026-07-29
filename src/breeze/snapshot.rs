use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

const MAX_SNAPSHOT_FILES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotResource {
    pub(crate) identity: String,
    pub(crate) name: String,
    pub(crate) descriptor_path: PathBuf,
    pub(crate) domains: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    directory: PathBuf,
    resources: Vec<SnapshotResource>,
}

impl Snapshot {
    pub(crate) fn load(directory: &Path) -> Result<Self> {
        ensure!(
            directory.is_dir(),
            "Breeze bypass snapshot directory does not exist or is not a directory: {}",
            directory.display()
        );
        let paths = snapshot_files(directory)?;
        ensure!(
            !paths.is_empty(),
            "Breeze bypass snapshot directory contains no regular files: {}",
            directory.display()
        );

        let mut resources = Vec::with_capacity(paths.len());
        for descriptor_path in paths {
            let identity = descriptor_path
                .file_name()
                .and_then(|value| value.to_str())
                .context("Breeze snapshot filename is not valid UTF-8")?
                .to_string();
            let source = fs::read_to_string(&descriptor_path).with_context(|| {
                format!(
                    "failed to read Breeze snapshot {}",
                    descriptor_path.display()
                )
            })?;
            let name = resource_name(&source, &identity);
            let mut domains = BTreeSet::new();
            extract_backend_domains(&source, &mut domains);
            resources.push(SnapshotResource {
                identity,
                name,
                descriptor_path,
                domains,
            });
        }

        Ok(Self {
            directory: directory.to_path_buf(),
            resources,
        })
    }

    pub(crate) fn file_count(&self) -> usize {
        self.resources.len()
    }

    pub(crate) fn resources(&self) -> &[SnapshotResource] {
        &self.resources
    }

    pub(crate) fn domains(&self) -> BTreeSet<String> {
        self.resources
            .iter()
            .flat_map(|resource| resource.domains.iter().cloned())
            .collect()
    }

    pub(crate) fn resolve(&self, selector: &str) -> Result<&SnapshotResource> {
        validate_selector(selector)?;
        let exact = self
            .resources
            .iter()
            .filter(|resource| resource.identity == selector)
            .collect::<Vec<_>>();
        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        ensure!(
            exact.is_empty(),
            "Breeze snapshot resource identity {selector:?} is ambiguous in {}",
            self.directory.display()
        );

        let named = self
            .resources
            .iter()
            .filter(|resource| resource.name == selector)
            .collect::<Vec<_>>();
        match named.as_slice() {
            [resource] => Ok(*resource),
            [] => bail!(
                "Breeze snapshot resource {selector:?} does not exist in {}",
                self.directory.display()
            ),
            resources => {
                let identities = resources
                    .iter()
                    .map(|resource| resource.identity.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "Breeze snapshot resource name {selector:?} is ambiguous in {}; use one exact descriptor identity: {identities}",
                    self.directory.display()
                )
            }
        }
    }
}

fn snapshot_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![directory.to_path_buf()];
    let mut files = Vec::new();
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).with_context(|| {
            format!(
                "failed to list Breeze snapshot directory {}",
                current.display()
            )
        })? {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read an entry under Breeze snapshot directory {}",
                    current.display()
                )
            })?;
            let file_type = entry.file_type().with_context(|| {
                format!(
                    "failed to inspect Breeze snapshot {}",
                    entry.path().display()
                )
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
                ensure!(
                    files.len() <= MAX_SNAPSHOT_FILES,
                    "Breeze snapshot directory {} exceeds the {} file safety limit",
                    directory.display(),
                    MAX_SNAPSHOT_FILES
                );
            }
        }
    }
    files.sort();
    Ok(files)
}

fn resource_name(source: &str, identity: &str) -> String {
    source
        .lines()
        .nth(1)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| identity.rsplit('+').next().unwrap_or(identity))
        .to_string()
}

fn extract_backend_domains(source: &str, domains: &mut BTreeSet<String>) {
    for token in source.split(|character: char| {
        character.is_ascii_whitespace()
            || matches!(character, ',' | '[' | ']' | '{' | '}' | '(' | ')' | ';')
    }) {
        let token =
            token.trim_matches(|character: char| matches!(character, '-' | '\'' | '"' | '`'));
        let Some((host, port)) = token.rsplit_once(':') else {
            continue;
        };
        if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            continue;
        }
        let host = normalize_domain(host);
        if is_hostname(&host) {
            domains.insert(host);
        }
    }
}

fn is_hostname(value: &str) -> bool {
    if value.len() > 253 || !value.contains('.') || value.parse::<IpAddr>().is_ok() {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_selector(selector: &str) -> Result<()> {
    ensure!(
        !selector.is_empty(),
        "Breeze snapshot resource must not be empty"
    );
    ensure!(
        selector == selector.trim() && !selector.contains(['\r', '\n', '/', '\\']),
        "Breeze snapshot resource must be one filename-safe line without surrounding whitespace"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(directory: &Path, identity: &str, name: &str, backends: &str) {
        fs::write(
            directory.join(identity),
            format!("123\n{name}\nbackends:\n- {backends}\n"),
        )
        .unwrap();
    }

    #[test]
    fn resolves_unique_short_name_or_exact_identity() {
        let directory = tempfile::tempdir().unwrap();
        let identity = "static.config+3+config+cloud+redis+user+usercounter";
        snapshot(
            directory.path(),
            identity,
            "usercounter",
            "RM7917.EXAMPLE.COM:7917,10.0.0.1:7917",
        );
        let loaded = Snapshot::load(directory.path()).unwrap();

        let short = loaded.resolve("usercounter").unwrap();
        let exact = loaded.resolve(identity).unwrap();

        assert_eq!(short, exact);
        assert_eq!(short.identity, identity);
        assert_eq!(
            short.domains,
            BTreeSet::from(["rm7917.example.com".to_string()])
        );
    }

    #[test]
    fn rejects_ambiguous_short_names_and_reports_exact_identities() {
        let directory = tempfile::tempdir().unwrap();
        snapshot(directory.path(), "first", "shared", "one.example.com:6379");
        snapshot(directory.path(), "second", "shared", "two.example.com:6379");
        let loaded = Snapshot::load(directory.path()).unwrap();

        let error = loaded.resolve("shared").unwrap_err().to_string();

        assert!(error.contains("ambiguous"));
        assert!(error.contains("first"));
        assert!(error.contains("second"));
        assert_eq!(loaded.resolve("first").unwrap().identity, "first");
    }
}
