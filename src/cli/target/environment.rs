use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};

const RESERVED: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "PATH",
    "PWD",
    "SHELL",
    "BASH_ENV",
    "ENV",
    "TRP_REPLAY_SESSION",
];

#[derive(Clone, Debug)]
pub(super) struct Assignment {
    pub(super) name: String,
    pub(super) value: OsString,
}

pub(super) fn load_files(paths: &[PathBuf]) -> Result<BTreeMap<String, OsString>> {
    let mut values = BTreeMap::new();
    for path in paths {
        let entries = dotenvy::from_path_iter(path)
            .with_context(|| format!("failed to read environment file {}", path.display()))?;
        for entry in entries {
            let (name, value) = entry
                .with_context(|| format!("failed to parse environment file {}", path.display()))?;
            validate_name(&name).map_err(anyhow::Error::msg)?;
            values.insert(name, OsString::from(value));
        }
    }

    for (name, value) in &mut values {
        if let Some(inherited) = std::env::var_os(name) {
            *value = inherited;
        }
    }
    Ok(values)
}

pub(super) fn validate_unique_assignments<'a>(
    assignments: impl IntoIterator<Item = &'a Assignment>,
) -> Result<()> {
    let mut names = BTreeSet::new();
    for assignment in assignments {
        ensure!(
            names.insert(&assignment.name),
            "environment variable {} was supplied more than once",
            assignment.name
        );
    }
    Ok(())
}

pub(super) fn parse_assignment(value: &str) -> std::result::Result<Assignment, String> {
    let (name, value) = value
        .split_once('=')
        .ok_or_else(|| "expected NAME=VALUE".to_string())?;
    validate_name(name)?;
    Ok(Assignment {
        name: name.to_string(),
        value: OsString::from(value),
    })
}

fn validate_name(name: &str) -> std::result::Result<(), String> {
    let mut characters = name.chars();
    if !matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(format!("invalid environment name: {name}"));
    }
    if RESERVED.contains(&name) || name.starts_with("SUDO_") {
        return Err(format!("cannot set reserved environment variable {name}"));
    }
    Ok(())
}

pub(super) fn assignment_argument(name: &str, value: &OsStr) -> OsString {
    let mut assignment = OsString::from(name);
    assignment.push("=");
    assignment.push(value);
    assignment
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn assignment_parser_rejects_reserved_and_invalid_names() {
        assert!(parse_assignment("APP_CONFIG=/tmp/app").is_ok());
        assert!(parse_assignment("HOME=/tmp/home").is_err());
        assert!(parse_assignment("SUDO_USER=other").is_err());
        assert!(parse_assignment("9APP=value").is_err());
        assert!(parse_assignment("APP").is_err());
    }

    #[test]
    fn later_environment_files_override_earlier_values() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.env");
        let second = directory.path().join("second.env");
        fs::write(&first, "TARGET_ONE=first\nTARGET_TWO=stable\n").unwrap();
        fs::write(&second, "TARGET_ONE=second\n").unwrap();

        let values = load_files(&[first, second]).unwrap();

        assert_eq!(values["TARGET_ONE"], "second");
        assert_eq!(values["TARGET_TWO"], "stable");
    }

    #[test]
    fn environment_files_reject_reserved_values() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("reserved.env");
        fs::write(&path, "HOME=/tmp/other\n").unwrap();

        let error = load_files(&[path]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("reserved environment variable HOME")
        );
    }
}
