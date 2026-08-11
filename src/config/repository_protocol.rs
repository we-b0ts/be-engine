use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::AppConfig;

#[derive(Debug, Clone)]
pub struct MotanProtocolConfigOptions {
    pub target_root: PathBuf,
    pub source_port: u16,
    pub gateway_port: u16,
    pub target_port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotanProtocolConfigResult {
    pub status: &'static str,
    pub protocol: &'static str,
    pub project_config: PathBuf,
    pub recorder_config: PathBuf,
    pub source_port: u16,
    pub gateway_port: u16,
    pub target_port: u16,
    pub validation_status: &'static str,
    pub preflight_command: &'static str,
    pub motan_replay_command: String,
}

pub fn enable_repository_motan_protocol(
    options: MotanProtocolConfigOptions,
) -> Result<MotanProtocolConfigResult> {
    validate_ports(
        options.source_port,
        options.gateway_port,
        options.target_port,
    )?;
    let target_root = fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    ensure!(target_root.is_dir(), "target root must be a directory");
    let project_update =
        crate::e2e_run::render_motan_protocol_update(&target_root, options.target_port)?;
    require_regular_file(&project_update.recorder_config, "recorder config")?;
    let recorder_raw = fs::read_to_string(&project_update.recorder_config).with_context(|| {
        format!(
            "failed to read recorder config {}",
            project_update.recorder_config.display()
        )
    })?;
    let current = toml::from_str::<AppConfig>(&recorder_raw)
        .context("recorder configuration is invalid before Motan update")?;
    let rules_declared = motan_rules_declared(&recorder_raw)?;
    let desired_listen = format!("0.0.0.0:{}", options.gateway_port);
    let desired_upstream = format!("127.0.0.1:{}", options.source_port);
    let recorder_changed = !current.motan_gateway.enabled
        || current.motan_gateway.listen.to_string() != desired_listen
        || current.motan_gateway.matched_upstream != desired_upstream
        || !rules_declared;
    let recorder_payload = if recorder_changed {
        let mut assignments = vec![
            ("enabled", "true".to_string()),
            ("listen", quoted(&desired_listen)),
            ("matched_upstream", quoted(&desired_upstream)),
        ];
        if !rules_declared {
            assignments.push(("rules", "[]".to_string()));
        }
        update_motan_gateway_table(&recorder_raw, &assignments)?.into_bytes()
    } else {
        recorder_raw.into_bytes()
    };
    let updated = toml::from_slice::<AppConfig>(&recorder_payload)
        .context("recorder configuration is invalid after Motan update")?;
    updated
        .validate()
        .context("recorder configuration failed validation after Motan update")?;
    validate_gateway_listener(&updated, options.gateway_port)?;

    let mut updates = Vec::new();
    if project_update.changed {
        updates.push((project_update.path.clone(), project_update.payload));
    }
    if recorder_changed {
        updates.push((project_update.recorder_config.clone(), recorder_payload));
    }
    match updates.len() {
        0 => {}
        1 => super::edit::write_atomic(&updates[0].0, &updates[0].1)?,
        _ => super::edit::write_many_atomic(&updates)?,
    }

    Ok(MotanProtocolConfigResult {
        status: if updates.is_empty() {
            "unchanged"
        } else {
            "updated"
        },
        protocol: "motan",
        project_config: project_update.path,
        recorder_config: project_update.recorder_config,
        source_port: options.source_port,
        gateway_port: options.gateway_port,
        target_port: options.target_port,
        validation_status: "not_run",
        preflight_command: "backend-rewrite init preflight",
        motan_replay_command: format!(
            "motan-replay --input-raw :{} --output-rpc 127.0.0.1:{}",
            options.source_port, options.gateway_port
        ),
    })
}

fn validate_ports(source_port: u16, gateway_port: u16, target_port: u16) -> Result<()> {
    ensure!(
        source_port > 0 && gateway_port > 0 && target_port > 0,
        "Motan source, gateway, and target ports must be greater than zero"
    );
    ensure!(
        source_port != gateway_port && source_port != target_port && gateway_port != target_port,
        "Motan source, gateway, and target ports must be distinct"
    );
    Ok(())
}

fn validate_gateway_listener(config: &AppConfig, gateway_port: u16) -> Result<()> {
    let conflicts = [
        (config.http.enabled, config.http.listen.port(), "http"),
        (
            config.http_gateway.enabled,
            config.http_gateway.listen.port(),
            "http_gateway",
        ),
        (
            config.tcp_gateway.enabled,
            config.tcp_gateway.listen.port(),
            "tcp_gateway",
        ),
    ];
    if let Some((_, _, owner)) = conflicts
        .into_iter()
        .find(|(enabled, port, _)| *enabled && *port == gateway_port)
    {
        anyhow::bail!("Motan gateway port {gateway_port} conflicts with enabled {owner}");
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} must be a regular file and not a symlink: {}",
        path.display()
    );
    Ok(())
}

fn quoted(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn motan_rules_declared(raw: &str) -> Result<bool> {
    let document = toml::from_str::<toml::Value>(raw)
        .context("failed to inspect Motan rules in recorder configuration")?;
    Ok(document
        .get("motan_gateway")
        .and_then(toml::Value::as_table)
        .is_some_and(|gateway| gateway.contains_key("rules")))
}

fn update_motan_gateway_table(raw: &str, assignments: &[(&str, String)]) -> Result<String> {
    let newline = if raw.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines = raw
        .split_inclusive(['\n'])
        .map(str::to_string)
        .collect::<Vec<_>>();
    if raw.is_empty() {
        lines.clear();
    } else if !raw.ends_with('\n') {
        let last = lines
            .last_mut()
            .context("recorder config has no final line")?;
        if last.ends_with('\r') {
            last.pop();
        }
    }
    let header = lines
        .iter()
        .position(|line| line.trim() == "[motan_gateway]");
    if let Some(header) = header {
        let end = lines
            .iter()
            .enumerate()
            .skip(header + 1)
            .find(|(_, line)| line.trim_start().starts_with('['))
            .map(|(index, _)| index)
            .unwrap_or(lines.len());
        let mut missing = Vec::new();
        for (key, value) in assignments {
            if let Some(line) = lines[header + 1..end]
                .iter_mut()
                .find(|line| assignment_key(line).is_some_and(|actual| actual == *key))
            {
                *line = format!("{key} = {value}{newline}");
            } else {
                missing.push(format!("{key} = {value}{newline}"));
            }
        }
        lines.splice(header + 1..header + 1, missing);
    } else {
        let child = lines.iter().position(|line| {
            let line = line.trim();
            line.starts_with("[motan_gateway.") || line.starts_with("[[motan_gateway.")
        });
        let mut section = Vec::with_capacity(assignments.len() + 2);
        section.push(format!("[motan_gateway]{newline}"));
        section.extend(
            assignments
                .iter()
                .map(|(key, value)| format!("{key} = {value}{newline}")),
        );
        section.push(newline.to_string());
        if let Some(child) = child {
            lines.splice(child..child, section);
        } else {
            if !lines.is_empty() && !lines.last().is_some_and(|line| line.ends_with('\n')) {
                lines.push(newline.to_string());
            }
            if !lines.is_empty() && !lines.last().is_some_and(|line| line.trim().is_empty()) {
                lines.push(newline.to_string());
            }
            lines.extend(section);
        }
    }
    let rendered = lines.concat();
    toml::from_str::<toml::Value>(&rendered)
        .context("Motan gateway update produced invalid TOML")?;
    Ok(rendered)
}

fn assignment_key(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if line.starts_with('#') || line.starts_with('[') {
        return None;
    }
    line.split_once('=').map(|(key, _)| key.trim())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn adds_motan_gateway_without_reformatting_existing_config() {
        let raw = "# keep\n[http_gateway]\nenabled = true\nlisten = \"0.0.0.0:17171\"\n";
        let updated = update_motan_gateway_table(
            raw,
            &[
                ("enabled", "true".to_string()),
                ("listen", quoted("0.0.0.0:18081")),
                ("matched_upstream", quoted("127.0.0.1:8080")),
            ],
        )
        .unwrap();

        assert!(updated.starts_with(raw));
        assert!(updated.contains("[motan_gateway]\n"));
        assert!(updated.contains("matched_upstream = \"127.0.0.1:8080\""));
    }

    #[test]
    fn updates_only_owned_motan_gateway_keys_and_keeps_rules() {
        let raw = concat!(
            "[motan_gateway]\n",
            "# keep this comment\n",
            "enabled = false\n",
            "listen = \"127.0.0.1:1\"\n",
            "matched_upstream = \"127.0.0.1:2\"\n",
            "max_cases_per_api = 7\n\n",
            "[[motan_gateway.rules]]\n",
            "name = \"rpc\"\n",
            "apis = [\"com.example.Echo#echo(java.lang.String)\"]\n",
        );
        let updated = update_motan_gateway_table(
            raw,
            &[
                ("enabled", "true".to_string()),
                ("listen", quoted("0.0.0.0:18081")),
                ("matched_upstream", quoted("127.0.0.1:8080")),
            ],
        )
        .unwrap();

        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("max_cases_per_api = 7"));
        assert!(updated.contains("[[motan_gateway.rules]]"));
        assert!(motan_rules_declared(&updated).unwrap());
        let parsed: AppConfig = toml::from_str(&updated).unwrap();
        assert!(parsed.motan_gateway.enabled);
        assert_eq!(parsed.motan_gateway.rules.len(), 1);
    }

    #[test]
    fn rejects_ambiguous_motan_ports() {
        assert!(validate_ports(8080, 8080, 8081).is_err());
        assert!(validate_ports(0, 18081, 8081).is_err());
    }

    #[test]
    fn converges_project_and_recorder_configuration_idempotently() {
        let target = initialized_target();
        let options = || MotanProtocolConfigOptions {
            target_root: target.path().to_path_buf(),
            source_port: 8080,
            gateway_port: 18_081,
            target_port: 8081,
        };

        let first = enable_repository_motan_protocol(options()).unwrap();
        assert_eq!(first.status, "updated");
        assert_eq!(first.validation_status, "not_run");
        assert_eq!(
            first.motan_replay_command,
            "motan-replay --input-raw :8080 --output-rpc 127.0.0.1:18081"
        );
        let project = fs::read_to_string(&first.project_config).unwrap();
        assert!(project.contains("  motan_port: 8081"));
        assert!(!project.contains("source_port"));
        assert!(!project.contains("gateway_port"));
        let recorder = fs::read_to_string(&first.recorder_config).unwrap();
        assert!(recorder.contains("# preserve recorder comments"));
        assert!(recorder.contains("[motan_gateway]"));
        assert!(recorder.contains("rules = []"));
        let parsed = AppConfig::load(&first.recorder_config).unwrap();
        assert!(parsed.motan_gateway.enabled);
        assert_eq!(parsed.motan_gateway.listen.to_string(), "0.0.0.0:18081");
        assert_eq!(parsed.motan_gateway.matched_upstream, "127.0.0.1:8080");

        let project_before = fs::read(&first.project_config).unwrap();
        let recorder_before = fs::read(&first.recorder_config).unwrap();
        let second = enable_repository_motan_protocol(options()).unwrap();
        assert_eq!(second.status, "unchanged");
        assert_eq!(fs::read(&second.project_config).unwrap(), project_before);
        assert_eq!(fs::read(&second.recorder_config).unwrap(), recorder_before);

        let without_explicit_rules = fs::read_to_string(&second.recorder_config)
            .unwrap()
            .replace(
                "matched_upstream = \"127.0.0.1:8080\"\nrules = []\n",
                "matched_upstream = \"127.0.0.1:8080\"\n",
            );
        fs::write(&second.recorder_config, without_explicit_rules).unwrap();
        let repaired_rules = enable_repository_motan_protocol(options()).unwrap();
        assert_eq!(repaired_rules.status, "updated");
        assert!(
            fs::read_to_string(&repaired_rules.recorder_config)
                .unwrap()
                .contains("rules = []")
        );

        let drifted = fs::read_to_string(&repaired_rules.recorder_config)
            .unwrap()
            .replace("127.0.0.1:8080", "127.0.0.1:9090");
        fs::write(&repaired_rules.recorder_config, drifted).unwrap();
        let repaired = enable_repository_motan_protocol(options()).unwrap();
        assert_eq!(repaired.status, "updated");
        assert_eq!(fs::read(&repaired.project_config).unwrap(), project_before);
        assert_eq!(
            AppConfig::load(repaired.recorder_config)
                .unwrap()
                .motan_gateway
                .matched_upstream,
            "127.0.0.1:8080"
        );
    }

    fn initialized_target() -> TempDir {
        let target = tempfile::tempdir().unwrap();
        let root = target.path();
        assert!(
            Command::new("git")
                .args(["init", "-q", "-b", "integration"])
                .arg(root)
                .status()
                .unwrap()
                .success()
        );
        fs::write(root.join(".gitignore"), "/.traffic-e2e/local/\n").unwrap();
        fs::create_dir_all(root.join(".traffic-e2e")).unwrap();
        fs::write(
            root.join(".traffic-e2e/verification.yaml"),
            "version: 2\nexpected_response: assertions_only\nrules: []\n",
        )
        .unwrap();
        fs::write(
            root.join(".traffic-e2e/recorder.toml"),
            concat!(
                "# preserve recorder comments\n",
                "[http_gateway.ready]\n",
                "enabled = true\n",
                "path = \"/healthz\"\n",
                "success_status = 404\n",
                "\n",
                "[[http_gateway.rules]]\n",
                "name = \"record-api\"\n",
                "methods = [\"GET\"]\n",
                "path_prefixes = [\"/\"]\n",
            ),
        )
        .unwrap();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["add", "."])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args([
                    "-c",
                    "user.name=E2E Test",
                    "-c",
                    "user.email=e2e-test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "initial",
                ])
                .status()
                .unwrap()
                .success()
        );
        crate::e2e_run::initialize_e2e_run(crate::E2eRunInitOptions {
            target_root: root.to_path_buf(),
            source_container: "source-app".to_string(),
            breeze_container: None,
            target_dockerfile: PathBuf::from(".traffic-e2e/Dockerfile.e2e"),
            target_startup: crate::StartupConfig::default(),
            target_http_host: "127.0.0.1".to_string(),
            target_port: 8081,
            replay_policy: PathBuf::from(".traffic-e2e/verification.yaml"),
            pr_base: "integration".to_string(),
            recorder_config: PathBuf::from(".traffic-e2e/recorder.toml"),
            recording_rule: "record-api".to_string(),
            force: false,
        })
        .unwrap();
        target
    }
}
