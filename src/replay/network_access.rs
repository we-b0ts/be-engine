use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use tokio::net::TcpStream;

use super::{
    ReplayProtocol, ReplayState, ReplayTarget, TargetKey, find_upward, normalize_host,
    register_replay_target,
};
use crate::recording_network::{RECORDING_NETWORK_FILENAME, RecordingNetworkManifest};

pub(super) async fn wait_for_unrecorded_payload(
    stream: &TcpStream,
    active_case: bool,
) -> Result<bool> {
    if active_case {
        return Ok(true);
    }
    let mut first_byte = [0_u8; 1];
    Ok(stream.peek(&mut first_byte).await? > 0)
}

pub(super) fn apply_recorded_endpoint_allowlist(
    root_dir: &Path,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
) -> Result<PathBuf> {
    let path = find_upward(root_dir, RECORDING_NETWORK_FILENAME).ok_or_else(|| {
        anyhow!(
            "recording network manifest {RECORDING_NETWORK_FILENAME} was not found for {}; \
             replay requires a recording created by the current traffic-e2e version",
            root_dir.display()
        )
    })?;
    let manifest = RecordingNetworkManifest::load(&path)?;
    let allowed = manifest
        .accessed_endpoints
        .into_iter()
        .map(|endpoint| TargetKey {
            host: normalize_host(&endpoint.host),
            port: endpoint.port,
        })
        .collect::<BTreeSet<_>>();
    targets.retain(|target, _| allowed.contains(target));
    for target in allowed {
        register_replay_target(targets, &target, ReplayProtocol::Auto)?;
    }
    Ok(path)
}

impl ReplayState {
    pub(super) fn fake_ip_for_dns(&mut self, domain: &str) -> Result<Ipv4Addr> {
        if let Some(target) = self
            .targets
            .iter()
            .find(|target| normalize_host(&target.host) == domain)
        {
            return Ok(target.fake_ip);
        }
        if let Some(fake_ip) = self.unrecorded_domain_ips.get(domain) {
            return Ok(*fake_ip);
        }

        let fake_ip = loop {
            if self.next_unrecorded_fake_offset >= self.fake_cidr.size.saturating_sub(1) {
                return Err(anyhow!(
                    "fake CIDR exhausted by recorded and rejected replay hosts"
                ));
            }
            let candidate = self
                .fake_cidr
                .ip_at(self.next_unrecorded_fake_offset)
                .ok_or_else(|| anyhow!("invalid next fake CIDR offset"))?;
            self.next_unrecorded_fake_offset += 1;
            if self.occupied_fake_ips.insert(candidate) {
                break candidate;
            }
        };
        self.unrecorded_domain_ips
            .insert(domain.to_string(), fake_ip);
        self.unrecorded_ip_domains
            .insert(fake_ip, domain.to_string());
        Ok(fake_ip)
    }

    pub(super) fn unrecorded_target_for(&self, fake_ip: Ipv4Addr, port: u16) -> Option<TargetKey> {
        let host = self
            .targets
            .iter()
            .find(|target| target.fake_ip == fake_ip)
            .map(|target| target.host.clone())
            .or_else(|| self.unrecorded_ip_domains.get(&fake_ip).cloned())?;
        Some(TargetKey { host, port })
    }

    pub(super) fn record_unrecorded_target(&mut self, target: TargetKey) {
        let case_id = self.active_case_id.clone().or_else(|| {
            (self.cases.len() == 1)
                .then(|| self.cases.keys().next().cloned())
                .flatten()
        });
        if self
            .unrecorded_targets
            .iter()
            .any(|event| event.case_id == case_id && event.target == target)
        {
            return;
        }
        self.unrecorded_targets.push(super::UnrecordedTargetReport {
            case_id,
            target,
            reason: super::UNRECORDED_ENDPOINT_REASON.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::{ReplayConfig, ReplayRuntime};

    #[test]
    fn allowlist_removes_dependency_targets_not_observed_during_recording() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join(RECORDING_NETWORK_FILENAME),
            r#"{"version":1,"resolved_domains":["allowed.test"],"accessed_endpoints":[{"host":"allowed.test","port":6379}]}"#,
        )
        .unwrap();
        let mut targets = BTreeMap::new();
        for host in ["allowed.test", "not-accessed.test"] {
            register_replay_target(
                &mut targets,
                &TargetKey {
                    host: host.to_string(),
                    port: 6379,
                },
                ReplayProtocol::Redis,
            )
            .unwrap();
        }

        let path = apply_recorded_endpoint_allowlist(temp.path(), &mut targets).unwrap();
        assert_eq!(path, temp.path().join(RECORDING_NETWORK_FILENAME));
        assert!(targets.contains_key(&TargetKey {
            host: "allowed.test".to_string(),
            port: 6379,
        }));
        assert!(!targets.contains_key(&TargetKey {
            host: "not-accessed.test".to_string(),
            port: 6379,
        }));
    }

    #[test]
    fn rejects_recordings_without_a_network_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let error = apply_recorded_endpoint_allowlist(temp.path(), &mut BTreeMap::new())
            .unwrap_err()
            .to_string();

        assert!(error.contains(RECORDING_NETWORK_FILENAME));
        assert!(error.contains("requires a recording created by the current traffic-e2e version"));
    }

    #[tokio::test]
    async fn unknown_domain_dns_gets_quarantine_ip_without_dirty_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case-a");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        tokio::fs::write(
            temp.path().join(RECORDING_NETWORK_FILENAME),
            r#"{"version":1,"resolved_domains":[],"accessed_endpoints":[]}"#,
        )
        .await
        .unwrap();
        let runtime = ReplayRuntime::load(
            ReplayConfig {
                case_dir,
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(temp.path().join("ca.pem")),
                ca_key_path: Some(temp.path().join("ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: Vec::new(),
                process_owned_dependencies: Vec::new(),
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut state = runtime.state.lock().await;
        let fake_ip = state.fake_ip_for_dns("new.example.test").unwrap();
        let target = state.unrecorded_target_for(fake_ip, 9301).unwrap();
        assert_eq!(target.host, "new.example.test");
        assert_eq!(target.port, 9301);

        let report = state.snapshot_report();
        assert!(!report.is_dirty());
        assert!(report.unrecorded_targets.is_empty());
    }

    #[tokio::test]
    async fn recorded_domain_payload_on_an_unrecorded_port_is_reported_once() {
        let temp = tempfile::tempdir().unwrap();
        let case_dir = temp.path().join("case-a");
        tokio::fs::create_dir_all(&case_dir).await.unwrap();
        tokio::fs::write(case_dir.join("dependencies.jsonl"), "")
            .await
            .unwrap();
        tokio::fs::write(
            temp.path().join(RECORDING_NETWORK_FILENAME),
            r#"{"version":1,"resolved_domains":["breeze.recording"],"accessed_endpoints":[{"host":"breeze.recording","port":9301}]}"#,
        )
        .await
        .unwrap();
        let runtime = ReplayRuntime::load(
            ReplayConfig {
                case_dir,
                selected_case_ids: Vec::new(),
                dns_listen: "127.0.0.1:0".parse().unwrap(),
                tcp_listen: "127.0.0.1:0".parse().unwrap(),
                fake_cidr: "198.18.0.0/15".to_string(),
                report_path: None,
                session_path: None,
                control_socket_path: None,
                ca_cert_path: Some(temp.path().join("ca.pem")),
                ca_key_path: Some(temp.path().join("ca-key.pem")),
                policy_path: None,
                http_ignore_query_params: Vec::new(),
                process_owned_dependencies: Vec::new(),
                allowed_unused_http: None,
            },
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut state = runtime.state.lock().await;
        let fake_ip = state.fake_ip_for_dns("breeze.recording").unwrap();
        let target = state.unrecorded_target_for(fake_ip, 9302).unwrap();
        assert_eq!(target.host, "breeze.recording");
        assert_eq!(target.port, 9302);
        state.record_unrecorded_target(target.clone());
        state.record_unrecorded_target(target);
        assert_eq!(state.snapshot_report().unrecorded_targets.len(), 1);
    }

    #[tokio::test]
    async fn unrecorded_connection_without_payload_is_not_an_exchange() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(client);

        assert!(!wait_for_unrecorded_payload(&server, false).await.unwrap());
    }

    #[tokio::test]
    async fn first_payload_byte_marks_an_unrecorded_exchange() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.write_all(b"x").await.unwrap();

        assert!(wait_for_unrecorded_payload(&server, false).await.unwrap());
    }

    #[tokio::test]
    async fn active_case_rejects_unrecorded_server_first_connection_immediately() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                wait_for_unrecorded_payload(&server, true),
            )
            .await
            .unwrap()
            .unwrap()
        );
    }
}
