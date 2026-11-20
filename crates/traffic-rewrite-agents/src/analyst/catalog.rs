use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use traffic_engine::config::api_catalog::{self, ApiCatalog};

use super::model::{CatalogDocument, RepositoryAnalysisSnapshot};

pub const CATALOG_PATH: &str = ".traffic-e2e/local/repository-analysis/catalog.json";
const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

pub struct LoadedCatalog {
    pub document: CatalogDocument,
    pub revision: String,
    pub path: PathBuf,
    pub apis: Option<ApiCatalog>,
}

impl LoadedCatalog {
    pub fn snapshot(&self) -> RepositoryAnalysisSnapshot {
        RepositoryAnalysisSnapshot {
            catalog_revision: self.revision.clone(),
            api_groups: self.document.api_groups.clone(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if let Some(apis) = &self.apis {
            let bytes = apis
                .clone()
                .with_routes(self.document.api_groups.clone())?
                .encode()?
                .into_bytes();
            check_size(bytes.len() as u64)?;
            return Ok(bytes);
        }
        encode(&self.document)
    }
}

pub fn load(root: &Path) -> Result<LoadedCatalog> {
    let path = root.join(api_catalog::PATH);
    if let Some(yaml) = ApiCatalog::read(&path)? {
        let apis = ApiCatalog::parse(&yaml).with_context(|| format!("load {}", path.display()))?;
        return Ok(LoadedCatalog {
            document: CatalogDocument {
                api_groups: apis.routes().clone(),
            },
            revision: digest(yaml.as_bytes()),
            path,
            apis: Some(apis),
        });
    }
    let path = root.join(CATALOG_PATH);
    let Some(bytes) = read(&path)? else {
        return Ok(LoadedCatalog {
            document: CatalogDocument::default(),
            revision: "absent".into(),
            path,
            apis: None,
        });
    };
    let document: CatalogDocument = decode(&bytes, "repository analysis catalog")?;
    validate(&document)?;
    Ok(LoadedCatalog {
        document,
        revision: digest(&bytes),
        path,
        apis: None,
    })
}

fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    if let Ok(metadata) = fs::metadata(path) {
        check_size(metadata.len())?;
    }
    match fs::read(path) {
        Ok(bytes) => {
            check_size(bytes.len() as u64)?;
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn check_size(len: u64) -> Result<()> {
    ensure!(
        len <= MAX_DOCUMENT_BYTES as u64,
        "repository analysis catalog is too large"
    );
    Ok(())
}

pub fn encode(document: &CatalogDocument) -> Result<Vec<u8>> {
    validate(document)?;
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    check_size(bytes.len() as u64)?;
    Ok(bytes)
}

pub fn publish_encoded(root: &Path, expected: &str, bytes: &[u8]) -> Result<()> {
    let current = load(root)?;
    ensure!(
        current.revision == expected,
        "repository analysis catalog changed during application; request fresh context"
    );
    if expected == "absent" {
        crate::config::edit::create_atomic(&current.path, bytes)
    } else {
        crate::config::edit::write_atomic(&current.path, bytes)
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

fn validate(document: &CatalogDocument) -> Result<()> {
    for (api, id) in &document.api_groups {
        api_catalog::validate_route(api)?;
        api_catalog::validate_group(id)?;
    }
    Ok(())
}
