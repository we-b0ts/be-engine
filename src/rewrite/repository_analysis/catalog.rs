use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::model::{
    CatalogDocument, RepositoryAnalysisGroup, RepositoryAnalysisSnapshot, SCHEMA_VERSION,
};

pub(super) const CATALOG_PATH: &str = ".traffic-e2e/local/repository-analysis/catalog.json";
const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct LoadedCatalog {
    pub document: CatalogDocument,
    pub revision: String,
}

impl LoadedCatalog {
    pub fn snapshot(&self) -> RepositoryAnalysisSnapshot {
        RepositoryAnalysisSnapshot {
            catalog_revision: self.revision.clone(),
            groups: self.document.groups.clone(),
            api_groups: self.document.api_groups.clone(),
        }
    }
}

pub(super) fn path(root: &Path) -> PathBuf {
    root.join(CATALOG_PATH)
}

pub(super) fn load(root: &Path) -> Result<LoadedCatalog> {
    if let Ok(metadata) = fs::metadata(path(root)) {
        ensure!(
            metadata.len() <= MAX_DOCUMENT_BYTES as u64,
            "repository analysis catalog is too large"
        );
    }
    let bytes = match fs::read(path(root)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LoadedCatalog {
                document: CatalogDocument {
                    schema_version: SCHEMA_VERSION,
                    ..Default::default()
                },
                revision: "absent".into(),
            });
        }
        Err(error) => return Err(error).context("read repository analysis catalog"),
    };
    let document: CatalogDocument = decode(&bytes, "repository analysis catalog")?;
    validate(&document)?;
    Ok(LoadedCatalog {
        document,
        revision: digest(&bytes),
    })
}

pub(super) fn publish(root: &Path, expected: &str, document: &CatalogDocument) -> Result<()> {
    validate(document)?;
    ensure!(
        load(root)?.revision == expected,
        "repository analysis catalog changed during application; request fresh context"
    );
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "repository analysis catalog is too large"
    );
    if expected == "absent" {
        crate::config::edit::create_atomic(&path(root), &bytes)
    } else {
        crate::config::edit::write_atomic(&path(root), &bytes)
    }
}

pub(super) fn read_submission<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::metadata(path).context("inspect repository analysis submission")?;
    ensure!(
        metadata.len() <= MAX_DOCUMENT_BYTES as u64,
        "repository analysis submission is too large"
    );
    let bytes = fs::read(path).context("read repository analysis submission")?;
    decode(&bytes, "repository analysis submission")
}

fn decode<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    let value =
        crate::json_value::parse_with_limit(bytes, MAX_DOCUMENT_BYTES).with_context(|| {
            format!("invalid {label}: expected bounded JSON without duplicate keys")
        })?;
    serde_json::from_value(value).with_context(|| format!("invalid {label}"))
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(super) fn group_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "group id must contain 1..=128 ASCII letters, digits, '.', '_' or '-'"
    );
    Ok(())
}

pub(super) fn group(group: &RepositoryAnalysisGroup) -> Result<()> {
    line("group summary", &group.summary)?;
    ensure!(
        !group.source_refs.is_empty(),
        "group analysis requires source_refs"
    );
    for (name, values) in [
        ("source reference", &group.source_refs),
        ("shared module", &group.shared_modules),
        ("write hotspot", &group.write_hotspots),
    ] {
        let mut unique = BTreeSet::new();
        for value in values {
            line(name, value)?;
            ensure!(unique.insert(value), "duplicate {name}");
        }
    }
    Ok(())
}

fn line(label: &str, value: &str) -> Result<()> {
    ensure!(
        value == value.trim() && !value.is_empty() && value.len() <= 4096,
        "{label} must be a nonempty trimmed value of at most 4096 bytes"
    );
    super::super::validate_single_line(label, value)
}

pub(super) fn route(route: &str) -> Result<()> {
    let parsed = route.parse::<crate::recording_api::RecordingApiScope>()?;
    ensure!(
        parsed.to_string() == route,
        "use canonical route identity {:?}",
        parsed.to_string()
    );
    Ok(())
}

fn validate(document: &CatalogDocument) -> Result<()> {
    ensure!(
        document.schema_version == SCHEMA_VERSION,
        "unsupported repository analysis catalog schema version {}",
        document.schema_version
    );
    for (id, metadata) in &document.groups {
        group_id(id)?;
        group(metadata)?;
    }
    for (api, id) in &document.api_groups {
        route(api)?;
        ensure!(
            document.groups.contains_key(id),
            "repository analysis route {api} references unknown group {id}"
        );
    }
    Ok(())
}
