use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplaySource {
    Bootstrap,
    Case,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub(super) struct TargetKey {
    pub(super) host: String,
    pub(super) port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ReplayTarget {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) fake_ip: Ipv4Addr,
    pub(super) protocol: ReplayProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayProtocol {
    Mysql,
    Http,
    Https,
    Redis,
    Memcached,
    Kafka,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayMode {
    Single,
    Collection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplayCaseStatus {
    Pending,
    Active,
    Ended,
}

#[derive(Debug, Clone)]
pub(super) struct ReplayCase {
    pub(super) id: String,
    pub(super) dir: PathBuf,
    pub(super) dependencies_path: PathBuf,
    pub(super) status: ReplayCaseStatus,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ReplayCaseReport {
    pub(super) case_id: String,
    pub(super) case_dir: String,
    pub(super) dependencies_path: String,
    pub(super) status: ReplayCaseStatus,
}

pub(super) fn register_replay_target(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    target: &TargetKey,
    protocol: ReplayProtocol,
) -> Result<()> {
    if let Some(existing) = targets.get(target) {
        if existing.protocol != protocol {
            return Err(anyhow!(
                "replay target {}:{} is recorded as both {:?} and {:?}",
                target.host,
                target.port,
                existing.protocol,
                protocol
            ));
        }
        return Ok(());
    }
    targets.insert(
        target.clone(),
        ReplayTarget {
            host: target.host.clone(),
            port: target.port,
            fake_ip: Ipv4Addr::UNSPECIFIED,
            protocol,
        },
    );
    Ok(())
}

pub(super) async fn discover_replay_cases(
    root_dir: &Path,
    selected_case_ids: &BTreeSet<String>,
) -> Result<(ReplayMode, BTreeMap<String, ReplayCase>, Option<String>)> {
    crate::case_kind::reject_online_compare(root_dir)?;
    let direct_dependencies = root_dir.join("dependencies.jsonl");
    if direct_dependencies.is_file() {
        let case_id = path_file_name(root_dir).unwrap_or_else(|| "case".to_string());
        let mut cases = BTreeMap::new();
        cases.insert(
            case_id.clone(),
            ReplayCase {
                id: case_id.clone(),
                dir: root_dir.to_path_buf(),
                dependencies_path: direct_dependencies,
                status: ReplayCaseStatus::Pending,
            },
        );
        ensure_selected_cases_exist(root_dir, &cases, selected_case_ids)?;
        cases.retain(|id, _| selected_case_ids.is_empty() || selected_case_ids.contains(id));
        return Ok((ReplayMode::Single, cases, Some(case_id)));
    }

    let mut cases = BTreeMap::new();
    let mut pending = vec![root_dir.to_path_buf()];
    while let Some(scan_dir) = pending.pop() {
        crate::case_kind::reject_online_compare(&scan_dir)?;
        let dependencies_path = scan_dir.join("dependencies.jsonl");
        if !dependencies_path.is_file() {
            let mut entries = tokio::fs::read_dir(&scan_dir).await.with_context(|| {
                format!(
                    "failed to read replay case collection {}",
                    scan_dir.display()
                )
            })?;
            while let Some(entry) = entries.next_entry().await.with_context(|| {
                format!(
                    "failed to scan replay case collection {}",
                    scan_dir.display()
                )
            })? {
                let file_type = entry.file_type().await.with_context(|| {
                    format!(
                        "failed to inspect replay case entry {}",
                        entry.path().display()
                    )
                })?;
                if !file_type.is_dir() {
                    continue;
                }
                let child = entry.path();
                if should_skip_replay_scan_dir(&child) {
                    continue;
                }
                pending.push(child);
            }
            continue;
        }

        let Some(case_id) = path_file_name(&scan_dir) else {
            continue;
        };
        if cases.contains_key(&case_id) {
            return Err(anyhow!(
                "duplicate replay case id {case_id:?} under {}; pass a narrower case collection or re-record with unique case ids",
                root_dir.display()
            ));
        }
        cases.insert(
            case_id.clone(),
            ReplayCase {
                id: case_id,
                dir: scan_dir,
                dependencies_path,
                status: ReplayCaseStatus::Pending,
            },
        );
    }
    if cases.is_empty() {
        return Err(anyhow!(
            "replay path {} is neither a case directory nor a collection/run directory with dependencies.jsonl case files",
            root_dir.display()
        ));
    }
    ensure_selected_cases_exist(root_dir, &cases, selected_case_ids)?;
    cases.retain(|id, _| selected_case_ids.is_empty() || selected_case_ids.contains(id));
    Ok((ReplayMode::Collection, cases, None))
}

fn ensure_selected_cases_exist(
    root_dir: &Path,
    cases: &BTreeMap<String, ReplayCase>,
    selected_case_ids: &BTreeSet<String>,
) -> Result<()> {
    let missing = selected_case_ids
        .iter()
        .filter(|case_id| !cases.contains_key(*case_id))
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "selected replay cases are not published under {}: {}",
        root_dir.display(),
        missing.join(", ")
    );
    Ok(())
}

fn should_skip_replay_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "failed" | "staging" | ".replay"))
}

fn path_file_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
}

pub(super) fn find_upward(start: &Path, filename: &str) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

pub(super) fn assign_fake_ips(
    targets: BTreeMap<TargetKey, ReplayTarget>,
    fake_cidr: Ipv4Cidr,
) -> Result<Vec<ReplayTarget>> {
    let mut out = Vec::with_capacity(targets.len());
    let mut host_ips = BTreeMap::new();
    for (_, mut target) in targets {
        let fake_ip = if let Some(fake_ip) = host_ips.get(&target.host) {
            *fake_ip
        } else {
            let offset = u32::try_from(host_ips.len() + 1).context("too many replay hosts")?;
            let fake_ip = fake_cidr
                .ip_at(offset)
                .ok_or_else(|| anyhow!("fake CIDR exhausted by replay hosts"))?;
            host_ips.insert(target.host.clone(), fake_ip);
            fake_ip
        };
        target.fake_ip = fake_ip;
        out.push(target);
    }
    Ok(out)
}

pub(super) fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod online_compare_tests {
    use super::*;

    #[tokio::test]
    async fn replay_discovery_rejects_online_compare_artifact() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("case-kind.json"),
            r#"{"version":1,"kind":"online_compare"}"#,
        )
        .unwrap();
        let error = discover_replay_cases(directory.path(), &BTreeSet::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("online compare artifacts are not replay cases"));
    }
}
