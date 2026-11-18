use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::model::{CatalogDocument, RepositoryAnalysisSnapshot};

pub const CATALOG_PATH: &str = ".traffic-e2e/local/repository-analysis/catalog.json";
const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub struct LoadedCatalog {
    pub document: CatalogDocument,
    pub revision: String,
}

impl LoadedCatalog {
    pub fn snapshot(&self) -> RepositoryAnalysisSnapshot {
        RepositoryAnalysisSnapshot {
            catalog_revision: self.revision.clone(),
            api_groups: self.document.api_groups.clone(),
        }
    }
}

pub fn path(root: &Path) -> PathBuf {
    root.join(CATALOG_PATH)
}

pub fn load(root: &Path) -> Result<LoadedCatalog> {
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
                document: CatalogDocument::default(),
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

pub fn publish(root: &Path, expected: &str, document: &CatalogDocument) -> Result<()> {
    let bytes = encode(document)?;
    publish_encoded(root, expected, &bytes)
}

pub fn encode(document: &CatalogDocument) -> Result<Vec<u8>> {
    validate(document)?;
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "repository analysis catalog is too large"
    );
    Ok(bytes)
}

pub fn publish_encoded(root: &Path, expected: &str, bytes: &[u8]) -> Result<()> {
    ensure!(
        load(root)?.revision == expected,
        "repository analysis catalog changed during application; request fresh context"
    );
    if expected == "absent" {
        crate::config::edit::create_atomic(&path(root), bytes)
    } else {
        crate::config::edit::write_atomic(&path(root), bytes)
    }
}

pub fn read_submission<T: DeserializeOwned>(path: &Path) -> Result<T> {
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

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn group_id(id: &str) -> Result<()> {
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

pub fn route(route: &str) -> Result<()> {
    let parsed = route.parse::<crate::recording_api::RecordingApiScope>()?;
    ensure!(
        parsed.to_string() == route,
        "use canonical route identity {:?}",
        parsed.to_string()
    );
    Ok(())
}

fn validate(document: &CatalogDocument) -> Result<()> {
    for (api, id) in &document.api_groups {
        route(api)?;
        group_id(id)?;
    }
    Ok(())
}
