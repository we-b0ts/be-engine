use std::path::Path;

use anyhow::{Context, Result, ensure};

pub(super) fn stage_assets(
    assets: &Path,
    configs: &[crate::runtime_output::RuntimeOutputConfig],
) -> Result<()> {
    let mut outputs = String::new();
    for config in configs {
        let path = config
            .container_path
            .to_str()
            .context("target runtime output path is not UTF-8")?;
        ensure!(
            !path.contains(['\r', '\n', '\t']),
            "target runtime output path contains an unsupported delimiter"
        );
        outputs.push_str(&config.id);
        outputs.push('\t');
        outputs.push_str(path);
        outputs.push('\n');
    }
    super::write_asset(&assets.join("target-runtime-outputs.tsv"), &outputs, 0o600)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn stages_id_and_container_path_only() {
        let directory = tempfile::tempdir().unwrap();
        stage_assets(
            directory.path(),
            &[crate::runtime_output::RuntimeOutputConfig {
                id: "application-logs".to_string(),
                container_path: PathBuf::from("/data1/weibo/logs"),
                mode: crate::runtime_output::RuntimeOutputMode::ReadWrite,
                retention: crate::runtime_output::RuntimeOutputRetention::Keep,
            }],
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(directory.path().join("target-runtime-outputs.tsv")).unwrap(),
            "application-logs\t/data1/weibo/logs\n"
        );
    }
}
