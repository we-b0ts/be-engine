use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};

use super::TargetQualityGateConfig;

pub(super) fn inferred_target_quality_gates(target_root: &Path) -> Vec<TargetQualityGateConfig> {
    if !target_root.join("Cargo.toml").is_file() {
        return Vec::new();
    }
    vec![
        TargetQualityGateConfig {
            name: "rust-format".to_string(),
            argv: ["cargo", "fmt", "--all", "--check"]
                .map(str::to_string)
                .to_vec(),
        },
        TargetQualityGateConfig {
            name: "rust-test".to_string(),
            argv: ["cargo", "test", "--workspace"]
                .map(str::to_string)
                .to_vec(),
        },
        TargetQualityGateConfig {
            name: "rust-clippy".to_string(),
            argv: [
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ]
            .map(str::to_string)
            .to_vec(),
        },
    ]
}

pub(super) fn validate_target_quality_gates(gates: &[TargetQualityGateConfig]) -> Result<()> {
    ensure!(
        gates.len() <= 8,
        "target.quality_gates must contain at most 8 commands"
    );
    let mut names = BTreeSet::new();
    for gate in gates {
        ensure!(
            gate.name == gate.name.trim()
                && !gate.name.is_empty()
                && gate.name.len() <= 128
                && !gate.name.contains(['\r', '\n']),
            "target quality gate names must be unique non-empty single lines of at most 128 bytes"
        );
        ensure!(
            names.insert(gate.name.as_str()),
            "target quality gate name {:?} is duplicated",
            gate.name
        );
        ensure!(
            !gate.argv.is_empty() && gate.argv.len() <= 32,
            "target quality gate {:?} argv must contain between 1 and 32 arguments",
            gate.name
        );
        ensure!(
            gate.argv[0] == gate.argv[0].trim(),
            "target quality gate {:?} executable must not have surrounding whitespace",
            gate.name
        );
        for argument in &gate.argv {
            ensure!(
                !argument.is_empty()
                    && argument.len() <= 4_096
                    && !argument.contains('\0')
                    && !argument.contains(['\r', '\n']),
                "target quality gate {:?} argv must contain non-empty single-line arguments of at most 4096 bytes",
                gate.name
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_names_and_empty_executables() {
        let duplicate = TargetQualityGateConfig {
            name: "check".to_string(),
            argv: vec!["true".to_string()],
        };
        assert!(validate_target_quality_gates(&[duplicate.clone(), duplicate]).is_err());
        assert!(
            validate_target_quality_gates(&[TargetQualityGateConfig {
                name: "check".to_string(),
                argv: vec![" ".to_string()],
            }])
            .is_err()
        );
    }
}
