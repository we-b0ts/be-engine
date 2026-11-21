use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use uuid::Uuid;

const ENVIRONMENT_FILE_MODE: u32 = 0o600;
const MAX_ENVIRONMENT_VARIABLES: usize = 256;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupEnvironmentChangeStatus {
    Created,
    Updated,
    Unchanged,
    Removed,
    Absent,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupEnvironmentList {
    pub path: PathBuf,
    pub variables: Vec<String>,
    pub overrides: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupEnvironmentPresence {
    pub name: String,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupEnvironmentComparison {
    pub name: String,
    pub exists: bool,
    pub equal: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupEnvironmentChange {
    pub name: String,
    pub status: StartupEnvironmentChangeStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupEnvironmentImport {
    pub path: PathBuf,
    pub variables: Vec<String>,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupEnvironmentValidation {
    pub status: &'static str,
    pub path: PathBuf,
    pub variables: Vec<String>,
    pub overrides: Vec<String>,
}

pub fn initialize_startup_environment(
    target_root: &Path,
    source: Option<&Path>,
) -> Result<StartupEnvironmentValidation> {
    let path = environment_path(target_root);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            require_regular_file(&path, &metadata)?;
            if let Some(source) = source {
                let source = fs::canonicalize(source).with_context(|| {
                    format!("failed to resolve environment file {}", source.display())
                })?;
                let destination = fs::canonicalize(&path).with_context(|| {
                    format!("failed to resolve environment file {}", path.display())
                })?;
                ensure!(
                    source == destination,
                    "{} already exists; refusing to replace it from {}",
                    path.display(),
                    source.display()
                );
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(ENVIRONMENT_FILE_MODE))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let values = match source {
                Some(source) => read_environment(source)?,
                None => BTreeMap::new(),
            };
            write_environment(&path, &values)?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    let overrides = read_environment(&path)?;
    let mut variables = source_environment(target_root)?;
    variables.extend(overrides.clone());
    Ok(StartupEnvironmentValidation {
        status: "valid",
        path: relative_environment_path(),
        variables: variables.into_keys().collect(),
        overrides: overrides.into_keys().collect(),
    })
}

pub fn list_startup_environment(target_root: &Path) -> Result<StartupEnvironmentList> {
    let overrides = load_environment(target_root)?;
    let values = effective_environment(target_root)?;
    Ok(StartupEnvironmentList {
        path: relative_environment_path(),
        variables: values.into_keys().collect(),
        overrides: overrides.into_keys().collect(),
    })
}

pub fn startup_environment_exists(
    target_root: &Path,
    name: &str,
) -> Result<StartupEnvironmentPresence> {
    validate_name(name)?;
    let values = effective_environment(target_root)?;
    Ok(StartupEnvironmentPresence {
        name: name.to_string(),
        exists: values.contains_key(name),
    })
}

pub fn startup_environment_equals(
    target_root: &Path,
    name: &str,
    expected: &str,
) -> Result<StartupEnvironmentComparison> {
    validate_name(name)?;
    validate_value(name, expected)?;
    let values = effective_environment(target_root)?;
    let actual = values.get(name);
    Ok(StartupEnvironmentComparison {
        name: name.to_string(),
        exists: actual.is_some(),
        equal: actual.is_some_and(|actual| constant_time_equal(actual, expected)),
    })
}

pub fn ensure_startup_environment(
    target_root: &Path,
    name: &str,
    value: &str,
) -> Result<StartupEnvironmentChange> {
    validate_name(name)?;
    validate_value(name, value)?;
    let path = ensure_environment_path(target_root)?;
    let mut values = read_environment(&path)?;
    let status = match values.get(name) {
        Some(existing) if constant_time_equal(existing, value) => {
            StartupEnvironmentChangeStatus::Unchanged
        }
        Some(_) => {
            values.insert(name.to_string(), value.to_string());
            write_environment(&path, &values)?;
            StartupEnvironmentChangeStatus::Updated
        }
        None => {
            if source_environment(target_root)?
                .get(name)
                .is_some_and(|existing| constant_time_equal(existing, value))
            {
                return Ok(StartupEnvironmentChange {
                    name: name.to_string(),
                    status: StartupEnvironmentChangeStatus::Unchanged,
                });
            }
            ensure!(
                values.len() < MAX_ENVIRONMENT_VARIABLES,
                "startup environment exceeds the limit of {MAX_ENVIRONMENT_VARIABLES} variables"
            );
            values.insert(name.to_string(), value.to_string());
            write_environment(&path, &values)?;
            StartupEnvironmentChangeStatus::Created
        }
    };
    Ok(StartupEnvironmentChange {
        name: name.to_string(),
        status,
    })
}

pub fn remove_startup_environment(
    target_root: &Path,
    name: &str,
) -> Result<StartupEnvironmentChange> {
    validate_name(name)?;
    let path = ensure_environment_path(target_root)?;
    let mut values = read_environment(&path)?;
    let status = if values.remove(name).is_some() {
        write_environment(&path, &values)?;
        StartupEnvironmentChangeStatus::Removed
    } else {
        StartupEnvironmentChangeStatus::Absent
    };
    Ok(StartupEnvironmentChange {
        name: name.to_string(),
        status,
    })
}

pub fn import_startup_environment(
    target_root: &Path,
    source: &Path,
) -> Result<StartupEnvironmentImport> {
    let imported = read_environment(source)?;
    let path = ensure_environment_path(target_root)?;
    let mut values = read_environment(&path)?;
    let mut created = 0;
    let mut updated = 0;
    let mut unchanged = 0;
    for (name, value) in &imported {
        match values.get(name) {
            Some(existing) if constant_time_equal(existing, value) => unchanged += 1,
            Some(_) => {
                values.insert(name.clone(), value.clone());
                updated += 1;
            }
            None => {
                values.insert(name.clone(), value.clone());
                created += 1;
            }
        }
    }
    ensure!(
        values.len() <= MAX_ENVIRONMENT_VARIABLES,
        "startup environment exceeds the limit of {MAX_ENVIRONMENT_VARIABLES} variables"
    );
    if created > 0 || updated > 0 {
        write_environment(&path, &values)?;
    }
    Ok(StartupEnvironmentImport {
        path: relative_environment_path(),
        variables: imported.into_keys().collect(),
        created,
        updated,
        unchanged,
    })
}

pub fn validate_startup_environment(target_root: &Path) -> Result<StartupEnvironmentValidation> {
    let overrides = load_environment(target_root)?;
    let values = effective_environment(target_root)?;
    Ok(StartupEnvironmentValidation {
        status: "valid",
        path: relative_environment_path(),
        variables: values.into_keys().collect(),
        overrides: overrides.into_keys().collect(),
    })
}

pub fn startup_environment_variable_names(target_root: &Path) -> Result<Vec<String>> {
    Ok(effective_environment(target_root)?.into_keys().collect())
}

pub fn write_docker_environment_file(path: &Path, target_root: &Path) -> Result<()> {
    let values = effective_environment(target_root)?;
    write_environment_file(path, &values, EnvironmentFileSyntax::Docker)
}

pub fn startup_environment_revision(target_root: &Path) -> Result<String> {
    let values = effective_environment(target_root)?;
    let mut hash = 0xcbf29ce484222325_u64;
    for (name, value) in values {
        for byte in name
            .bytes()
            .chain(std::iter::once(0))
            .chain(value.bytes())
            .chain(std::iter::once(0))
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Ok(format!("fnv1a64:{hash:016x}"))
}

fn load_environment(target_root: &Path) -> Result<BTreeMap<String, String>> {
    let path = ensure_environment_path(target_root)?;
    read_environment(&path)
}

pub fn startup_environment_value(target_root: &Path, name: &str) -> Result<Option<String>> {
    Ok(effective_environment(target_root)?.remove(name))
}

fn effective_environment(target_root: &Path) -> Result<BTreeMap<String, String>> {
    let mut values = source_environment(target_root)?;
    values.extend(load_environment(target_root)?);
    Ok(values)
}

fn source_environment(target_root: &Path) -> Result<BTreeMap<String, String>> {
    let source_manifest = target_root.join(crate::repository::LOCAL_SOURCE_MANIFEST_PATH);
    if source_manifest.exists() {
        crate::source_snapshot::target_environment(target_root)
    } else {
        Ok(BTreeMap::new())
    }
}

fn ensure_environment_path(target_root: &Path) -> Result<PathBuf> {
    initialize_startup_environment(target_root, None)?;
    Ok(environment_path(target_root))
}

fn environment_path(target_root: &Path) -> PathBuf {
    target_root.join(crate::repository::LOCAL_TARGET_ENV_PATH)
}

fn relative_environment_path() -> PathBuf {
    PathBuf::from(crate::repository::LOCAL_TARGET_ENV_PATH)
}

fn read_environment(path: &Path) -> Result<BTreeMap<String, String>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect environment file {}", path.display()))?;
    require_regular_file(path, &metadata)?;
    let entries = dotenvy::from_path_iter(path)
        .with_context(|| format!("failed to read environment file {}", path.display()))?;
    let mut values = BTreeMap::new();
    for (index, entry) in entries.enumerate() {
        let (name, value) = entry.map_err(|_| {
            anyhow::anyhow!(
                "failed to parse environment file {} at entry {}",
                path.display(),
                index + 1
            )
        })?;
        validate_name(&name)?;
        validate_value(&name, &value)?;
        ensure!(
            values.insert(name.clone(), value).is_none(),
            "environment file {} declares {name:?} more than once",
            path.display()
        );
    }
    ensure!(
        values.len() <= MAX_ENVIRONMENT_VARIABLES,
        "startup environment exceeds the limit of {MAX_ENVIRONMENT_VARIABLES} variables"
    );
    Ok(values)
}

fn validate_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    ensure!(
        bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()),
        "invalid startup environment variable name {name:?}"
    );
    ensure!(
        !name.to_ascii_uppercase().starts_with("TRAFFIC_E2E_"),
        "startup environment must use an application-owned name, got {name:?}"
    );
    Ok(())
}

fn validate_value(name: &str, value: &str) -> Result<()> {
    ensure!(
        !value.contains(['\0', '\r', '\n']),
        "startup environment {name:?} contains a value unsupported by Docker env files"
    );
    Ok(())
}

fn write_environment(path: &Path, values: &BTreeMap<String, String>) -> Result<()> {
    write_environment_file(path, values, EnvironmentFileSyntax::Dotenv)
}

#[derive(Clone, Copy)]
enum EnvironmentFileSyntax {
    Dotenv,
    Docker,
}

fn write_environment_file(
    path: &Path,
    values: &BTreeMap<String, String>,
    syntax: EnvironmentFileSyntax,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create environment directory {}",
                parent.display()
            )
        })?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        require_regular_file(path, &metadata)?;
    }
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("env"),
        Uuid::new_v4().simple()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ENVIRONMENT_FILE_MODE)
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        for (name, value) in values {
            validate_name(name)?;
            validate_value(name, value)?;
            match syntax {
                EnvironmentFileSyntax::Dotenv => write_dotenv_entry(&mut file, name, value)?,
                EnvironmentFileSyntax::Docker => writeln!(file, "{name}={value}")?,
            }
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to publish environment file {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(ENVIRONMENT_FILE_MODE))?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_dotenv_entry(file: &mut File, name: &str, value: &str) -> std::io::Result<()> {
    write!(file, "{name}='")?;
    for character in value.chars() {
        if character == '\'' {
            write!(file, "'\\''")?;
        } else {
            write!(file, "{character}")?;
        }
    }
    writeln!(file, "'")
}

fn require_regular_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "environment file must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

fn constant_time_equal(actual: &str, expected: &str) -> bool {
    let mut difference = actual.len() ^ expected.len();
    let length = actual.len().max(expected.len());
    for index in 0..length {
        difference |= usize::from(
            actual.as_bytes().get(index).copied().unwrap_or(0)
                ^ expected.as_bytes().get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

/// Dependency paths for a resolved effective startup environment, without values.
pub fn startup_environment_witness_paths(target_root: &Path) -> Result<Vec<PathBuf>> {
    effective_environment(target_root)?;
    let mut paths = vec![environment_path(target_root)];
    if target_root
        .join(crate::repository::LOCAL_SOURCE_MANIFEST_PATH)
        .exists()
    {
        paths.extend(crate::source_snapshot::target_environment_witness_paths(
            target_root,
        )?);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_manages_the_canonical_environment_without_returning_values() {
        let target = tempfile::tempdir().unwrap();
        let initialized = initialize_startup_environment(target.path(), None).unwrap();
        assert!(target.path().join(&initialized.path).is_file());
        assert!(initialized.variables.is_empty());

        let created = ensure_startup_environment(target.path(), "DATABASE_URL", "secret").unwrap();
        assert_eq!(created.status, StartupEnvironmentChangeStatus::Created);
        assert!(
            startup_environment_equals(target.path(), "DATABASE_URL", "secret")
                .unwrap()
                .equal
        );
        assert!(
            !startup_environment_equals(target.path(), "DATABASE_URL", "other")
                .unwrap()
                .equal
        );
        assert_eq!(
            list_startup_environment(target.path()).unwrap().variables,
            ["DATABASE_URL"]
        );

        let removed = remove_startup_environment(target.path(), "DATABASE_URL").unwrap();
        assert_eq!(removed.status, StartupEnvironmentChangeStatus::Removed);
    }

    #[test]
    fn canonical_dotenv_round_trips_values_while_docker_projection_is_literal() {
        let target = tempfile::tempdir().unwrap();
        let value = " $TOKEN='quoted' # literal\\path ";
        ensure_startup_environment(target.path(), "TOKEN", value).unwrap();
        assert!(
            startup_environment_equals(target.path(), "TOKEN", value)
                .unwrap()
                .equal
        );

        let projection = target.path().join("docker.env");
        write_docker_environment_file(&projection, target.path()).unwrap();
        assert_eq!(
            fs::read_to_string(projection).unwrap(),
            format!("TOKEN={value}\n")
        );
    }

    #[test]
    fn import_merges_values_without_returning_them() {
        let target = tempfile::tempdir().unwrap();
        let source = target.path().join("input.env");
        fs::write(&source, "ONE=first\nTWO=second\n").unwrap();

        let report = import_startup_environment(target.path(), &source).unwrap();
        assert_eq!(report.created, 2);
        assert_eq!(report.variables, ["ONE", "TWO"]);
        assert!(
            startup_environment_equals(target.path(), "TWO", "second")
                .unwrap()
                .equal
        );
    }

    #[test]
    fn rejects_reserved_names_duplicates_and_multiline_values() {
        let target = tempfile::tempdir().unwrap();
        let source = target.path().join("input.env");
        fs::write(&source, "ONE=first\nONE=second\n").unwrap();
        assert!(import_startup_environment(target.path(), &source).is_err());
        assert!(ensure_startup_environment(target.path(), "TRAFFIC_E2E_TOKEN", "value").is_err());
        assert!(ensure_startup_environment(target.path(), "TOKEN", "one\ntwo").is_err());
    }
}
