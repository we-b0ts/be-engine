//! A failed connect cannot steal an earlier successful connection to its endpoint.
use super::*;
use control::dependency_tail::{RecordedReference, recorded_reference};

struct Normal {
    reference: RecordedReference,
    completed: DateTime<Utc>,
}

#[derive(Default)]
struct EndpointHistory {
    connected: bool,
    completed: Vec<Normal>,
}

fn endpoint(event: &Value) -> Result<Option<TargetKey>> {
    if let (Some(host), Some(port)) = (
        event["target_host"].as_str(),
        event["target_port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok()),
    ) {
        return Ok(Some(TargetKey {
            host: normalize_host(host),
            port,
        }));
    }
    if event["event_type"] != "http_exchange" {
        return Ok(None);
    }
    let authority = event["authority"]
        .as_str()
        .context("mixed connection failure requires the HTTP physical authority")?
        .parse::<hyper::http::uri::Authority>()
        .context("invalid HTTP authority before a failed connect")?;
    let default_port = match event["scheme"].as_str() {
        Some("http" | "fake_ip_http" | "http_gateway") => 80,
        Some("https" | "fake_ip_https") => 443,
        _ => anyhow::bail!("unsupported HTTP scheme before a failed connect"),
    };
    Ok(Some(TargetKey {
        host: normalize_host(authority.host()),
        port: authority.port_u16().unwrap_or(default_port),
    }))
}

pub(super) async fn prepare(inventory: &mut Inventory, case: &str, path: &Path) -> Result<()> {
    let selected = inventory
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.case_id == case)
        .map(|(index, entry)| (index, entry.record.clone()))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(());
    }
    let mut histories = selected
        .iter()
        .map(|(_, record)| {
            (
                TargetKey {
                    host: normalize_host(&record.target_host),
                    port: record.target_port,
                },
                EndpointHistory::default(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let bytes = crate::dependency_index::scoped::read_bytes(path)?;
    let mut lines = tokio::io::BufReader::new(bytes.as_slice()).lines();
    let mut normal_count = 0usize;
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(&line)?;
        let Some(key) = endpoint(&event)? else {
            continue;
        };
        let Some(history) = histories.get_mut(&key) else {
            continue;
        };
        let kind = event["event_type"].as_str().unwrap_or_default();
        if kind.ends_with("_connection") {
            history.connected |= event["error"].is_null() && event["replay_safe"] != false;
            continue;
        }
        if kind == "dependency_connect_failure" {
            continue;
        }
        let Some(reference) = recorded_reference(&event).with_context(|| {
            format!(
                "cannot prove normal connection ordering before a failed connect at {}:{}",
                key.host, key.port
            )
        })?
        else {
            continue;
        };
        let completed = event["timestamp"]
            .as_str()
            .context("mixed connection failure requires recorded completion clocks")?
            .parse()
            .context("invalid normal dependency completion clock")?;
        normal_count += 1;
        ensure!(
            normal_count <= MAX_FAILURES,
            "mixed connection predecessor inventory exceeds its bound"
        );
        history.completed.push(Normal {
            reference,
            completed,
        });
    }
    let mut grouped = BTreeMap::<TargetKey, Vec<_>>::new();
    for (index, record) in selected {
        grouped
            .entry(TargetKey {
                host: normalize_host(&record.target_host),
                port: record.target_port,
            })
            .or_default()
            .push((index, record));
    }
    let mut predecessor_count = 0usize;
    for (key, mut failures) in grouped {
        failures.sort_by_key(|(index, record)| (record.timestamp, *index));
        let only_cleanup = failures
            .iter()
            .all(|(_, record)| record.failure_kind == "engine_cancelled");
        let history = &histories[&key];
        let mut previous: Option<RecordedFailure> = None;
        for (index, record) in failures {
            let started = record
                .timestamp
                .checked_sub_signed(chrono::TimeDelta::milliseconds(record.duration_ms as i64))
                .context("connection failure start clock is out of range")?;
            let predecessors = if let Some(previous) = previous.filter(|_| !only_cleanup) {
                ensure!(
                    previous.timestamp <= started,
                    "overlapping failed connections at {}:{} have ambiguous physical ownership",
                    key.host,
                    key.port
                );
                vec![RecordedReference::Connect {
                    event_id: previous.id,
                }]
            } else {
                let mut predecessors = Vec::with_capacity(history.completed.len());
                for normal in &history.completed {
                    ensure!(
                        normal.completed <= started,
                        "ambiguous normal and failed connections overlap or follow a failed connect at {}:{}; their physical ownership cannot be inferred",
                        key.host,
                        key.port
                    );
                    predecessors.push(normal.reference);
                }
                ensure!(
                    !history.connected || !predecessors.is_empty(),
                    "ambiguous successful and failed connections at {}:{} have no consumed business predecessor",
                    key.host,
                    key.port
                );
                predecessors
            };
            predecessor_count += predecessors.len();
            ensure!(
                predecessor_count <= MAX_FAILURES,
                "connection predecessor decisions exceed their bound"
            );
            inventory.entries[index].predecessors = predecessors;
            previous = Some(record);
        }
    }
    Ok(())
}
