use super::*;

pub use traffic_replay::ReplaySource;

pub use traffic_protocol::connection::Endpoint as TargetKey;

#[derive(Debug, Clone, Serialize)]
pub struct ReplayTarget {
    pub host: String,
    pub port: u16,
    pub fake_ip: Ipv4Addr,
    pub protocol: ReplayProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReplayProtocol(traffic_protocol::ProtocolId);

#[allow(non_upper_case_globals)]
impl ReplayProtocol {
    pub const Auto: Self = Self(traffic_protocol::ProtocolId::new("auto"));

    pub const fn new(protocol: traffic_protocol::ProtocolId) -> Self {
        Self(protocol)
    }
    pub fn registered(protocol: impl Into<traffic_protocol::ProtocolId>) -> Self {
        Self(protocol.into())
    }
    pub fn id(self) -> traffic_protocol::ProtocolId {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    Single,
    Collection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCaseStatus {
    Pending,
    Active,
    Ended,
}

#[derive(Debug, Clone)]
pub struct ReplayCase {
    pub id: String,
    pub dir: PathBuf,
    pub dependencies_path: PathBuf,
    pub status: ReplayCaseStatus,
}

impl ReplayCase {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn directory(&self) -> &Path {
        &self.dir
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayCaseReport {
    pub case_id: String,
    pub case_dir: String,
    pub dependencies_path: String,
    pub status: ReplayCaseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_request_started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_request_started_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub fn register_replay_target(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    target: &TargetKey,
    protocol: ReplayProtocol,
) -> Result<()> {
    register_replay_target_at(targets, target, protocol, None)
}

pub fn register_replay_target_at(
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    target: &TargetKey,
    protocol: ReplayProtocol,
    advertised_ip: Option<Ipv4Addr>,
) -> Result<()> {
    if let Some(existing) = targets.get_mut(target) {
        if existing.protocol != protocol {
            if existing.protocol == ReplayProtocol::Auto {
                existing.protocol = protocol;
            } else if protocol != ReplayProtocol::Auto {
                return Err(anyhow!(
                    "replay target {}:{} is recorded as both {:?} and {:?}",
                    target.host,
                    target.port,
                    existing.protocol,
                    protocol
                ));
            }
        }
        if let Some(advertised_ip) = advertised_ip
            && existing.fake_ip != Ipv4Addr::UNSPECIFIED
            && existing.fake_ip != advertised_ip
        {
            return Err(anyhow!(
                "replay target {}:{} is recorded with conflicting advertised IPs {} and {}",
                target.host,
                target.port,
                existing.fake_ip,
                advertised_ip
            ));
        }
        if let Some(advertised_ip) = advertised_ip {
            existing.fake_ip = advertised_ip;
        }
        return Ok(());
    }
    targets.insert(
        target.clone(),
        ReplayTarget {
            host: target.host.clone(),
            port: target.port,
            fake_ip: advertised_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            protocol,
        },
    );
    Ok(())
}

pub async fn discover_replay_cases(
    root_dir: &Path,
    selected_case_ids: &BTreeSet<String>,
) -> Result<(ReplayMode, BTreeMap<String, ReplayCase>, Option<String>)> {
    if crate::dependency_index::recording::root(root_dir).is_some() {
        let (_, files) = crate::dependency_index::recording::cases(root_dir)?;
        let mut cases = BTreeMap::new();
        for dependencies_path in files {
            let dir = dependencies_path
                .parent()
                .context("Case scope has no directory")?
                .to_path_buf();
            let id = path_file_name(&dir).context("Case directory has no identity")?;
            ensure!(
                cases
                    .insert(
                        id.clone(),
                        ReplayCase {
                            id,
                            dir,
                            dependencies_path,
                            status: ReplayCaseStatus::Pending
                        }
                    )
                    .is_none(),
                "duplicate manifest Case"
            );
        }
        ensure!(
            !cases.is_empty(),
            "selected recording scope contains no complete Cases"
        );
        ensure_selected_cases_exist(root_dir, &cases, selected_case_ids)?;
        cases.retain(|id, _| selected_case_ids.is_empty() || selected_case_ids.contains(id));
        let single = root_dir
            .join(crate::dependency_index::scoped::CASE_SCOPE)
            .is_file();
        let active = if single {
            cases.keys().next().cloned()
        } else {
            None
        };
        return Ok((
            if single {
                ReplayMode::Single
            } else {
                ReplayMode::Collection
            },
            cases,
            active,
        ));
    }
    #[cfg(not(any(test, feature = "test-support")))]
    anyhow::bail!(
        "recording requires the current central dependency manifest; old recording semantics are unsupported"
    );
    #[cfg(any(test, feature = "test-support"))]
    {
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

#[cfg(any(test, feature = "test-support"))]
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

pub fn find_upward(start: &Path, filename: &str) -> Option<PathBuf> {
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

pub fn assign_fake_ips(
    targets: BTreeMap<TargetKey, ReplayTarget>,
    fake_cidr: Ipv4Cidr,
) -> Result<Vec<ReplayTarget>> {
    let mut out = Vec::with_capacity(targets.len());
    let mut host_ips = BTreeMap::new();
    let mut reserved_ips = BTreeMap::new();
    for target in targets.values() {
        if target.fake_ip == Ipv4Addr::UNSPECIFIED {
            continue;
        }
        let offset = fake_cidr.offset_of(target.fake_ip).ok_or_else(|| {
            anyhow!(
                "recorded advertised IP {} for {}:{} is outside replay fake CIDR",
                target.fake_ip,
                target.host,
                target.port
            )
        })?;
        ensure!(
            offset > 0 && offset < fake_cidr.size.saturating_sub(1),
            "recorded advertised IP {} for {}:{} is not a usable replay fake IP",
            target.fake_ip,
            target.host,
            target.port
        );
        if let Some(existing_host) = reserved_ips.insert(target.fake_ip, target.host.clone()) {
            ensure!(
                existing_host == target.host,
                "recorded advertised IP {} is shared by replay hosts {:?} and {:?}",
                target.fake_ip,
                existing_host,
                target.host
            );
        }
        if let Some(existing_ip) = host_ips.insert(target.host.clone(), target.fake_ip) {
            ensure!(
                existing_ip == target.fake_ip,
                "replay host {:?} has conflicting advertised IPs {} and {}",
                target.host,
                existing_ip,
                target.fake_ip
            );
        }
    }
    let mut next_offset = 1_u32;
    for (_, mut target) in targets {
        let fake_ip = if target.fake_ip != Ipv4Addr::UNSPECIFIED {
            target.fake_ip
        } else if let Some(fake_ip) = host_ips.get(&target.host) {
            *fake_ip
        } else {
            let fake_ip = loop {
                let candidate = fake_cidr
                    .ip_at(next_offset)
                    .ok_or_else(|| anyhow!("fake CIDR exhausted by replay hosts"))?;
                next_offset = next_offset.saturating_add(1);
                if next_offset >= fake_cidr.size {
                    return Err(anyhow!("fake CIDR exhausted by replay hosts"));
                }
                if !reserved_ips.contains_key(&candidate) {
                    break candidate;
                }
            };
            host_ips.insert(target.host.clone(), fake_ip);
            reserved_ips.insert(fake_ip, target.host.clone());
            fake_ip
        };
        target.fake_ip = fake_ip;
        out.push(target);
    }
    Ok(out)
}

pub use traffic_protocol::observation::normalize_host;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_fake_ip_assignment_reserves_recorded_advertised_addresses() {
        let mut targets = BTreeMap::new();
        register_replay_target_at(
            &mut targets,
            &TargetKey {
                host: "vintage-node.trp.test".to_string(),
                port: 8881,
            },
            ReplayProtocol::Redis,
            Some("198.19.0.1".parse().unwrap()),
        )
        .unwrap();
        register_replay_target(
            &mut targets,
            &TargetKey {
                host: "config.example.test".to_string(),
                port: 80,
            },
            ReplayProtocol::Http,
        )
        .unwrap();

        let assigned = assign_fake_ips(targets, Ipv4Cidr::parse("198.19.0.0/16").unwrap()).unwrap();
        let vintage = assigned
            .iter()
            .find(|target| target.host == "vintage-node.trp.test")
            .unwrap();
        let config = assigned
            .iter()
            .find(|target| target.host == "config.example.test")
            .unwrap();
        assert_eq!(vintage.fake_ip, "198.19.0.1".parse::<Ipv4Addr>().unwrap());
        assert_ne!(config.fake_ip, vintage.fake_ip);
    }

    #[test]
    fn recorded_exchange_resolves_auto_discovered_target_protocol() {
        let mut targets = BTreeMap::new();
        let target = TargetKey {
            host: "vintage-node.trp.test".to_string(),
            port: 3120,
        };
        register_replay_target_at(
            &mut targets,
            &target,
            ReplayProtocol::Auto,
            Some("198.19.0.8".parse().unwrap()),
        )
        .unwrap();

        register_replay_target(&mut targets, &target, ReplayProtocol::Redis).unwrap();

        let target = targets.get(&target).unwrap();
        assert_eq!(target.protocol, ReplayProtocol::Redis);
        assert_eq!(target.fake_ip, "198.19.0.8".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn replay_rejects_conflicting_recorded_advertised_addresses() {
        let mut targets = BTreeMap::new();
        for host in ["node-a.trp.test", "node-b.trp.test"] {
            register_replay_target_at(
                &mut targets,
                &TargetKey {
                    host: host.to_string(),
                    port: 8881,
                },
                ReplayProtocol::Redis,
                Some("198.19.0.9".parse().unwrap()),
            )
            .unwrap();
        }

        let error = assign_fake_ips(targets, Ipv4Cidr::parse("198.19.0.0/16").unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("shared by replay hosts"));
    }
}
