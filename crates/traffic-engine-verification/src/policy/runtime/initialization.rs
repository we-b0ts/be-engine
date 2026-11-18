use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::config::edit::create_atomic;

const POLICY_PATH: &str = ".traffic-e2e/policy.yaml";

#[derive(Debug, Clone)]
pub struct ReplayPolicyInitOptions {
    pub target_root: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayPolicyInitResult {
    pub policy: PathBuf,
    pub format: &'static str,
}

pub fn initialize_replay_policy(
    options: ReplayPolicyInitOptions,
) -> Result<ReplayPolicyInitResult> {
    let target_root = fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let rendered = render_validated_replay_policy()?;

    let project = target_root.join(".traffic-e2e/project.yaml");
    let policy_path = if project.exists() {
        crate::config::resolve_unified_policy_path(&project)?
    } else {
        target_root.join(POLICY_PATH)
    };
    create_atomic(&policy_path, rendered.as_bytes())?;
    Ok(ReplayPolicyInitResult {
        policy: policy_path,
        format: crate::policy::POLICY_FORMAT,
    })
}

pub fn render_validated_replay_policy() -> Result<String> {
    crate::config::native_policy::empty_policy()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::policy::runtime::validate_replay_policy;

    #[test]
    fn initializes_empty_verification_policy_once() {
        let target = tempdir().unwrap();
        let result = initialize_replay_policy(ReplayPolicyInitOptions {
            target_root: target.path().to_path_buf(),
        })
        .unwrap();
        let report = validate_replay_policy(&result.policy).unwrap();
        assert!(result.policy.ends_with(".traffic-e2e/policy.yaml"));
        assert_eq!(result.format, crate::policy::POLICY_FORMAT);
        assert_eq!(report.version, 1);
        assert!(report.dependency_rule_ids.is_empty());
        assert!(report.response_rule_ids.is_empty());

        let error = initialize_replay_policy(ReplayPolicyInitOptions {
            target_root: target.path().to_path_buf(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
    }
}
