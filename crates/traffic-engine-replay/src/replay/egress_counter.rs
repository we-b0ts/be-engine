//! Optional rejection counts are diagnostic context, never a verification gate.
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ReplayEgressCounterReader {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEgressCounterSnapshot {
    pub generation: String,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
}

#[derive(Debug, Clone)]
pub struct Sample {
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    counters: Option<ReplayEgressCounterSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayEgressRejections {
    pub case_id: String,
    pub observed_from: DateTime<Utc>,
    pub observed_until: DateTime<Utc>,
    /// None means the counters could not be read or were reset/replaced.
    pub rejected_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl ReplayEgressCounterReader {
    pub async fn sample(&self) -> Sample {
        let started_at = Utc::now();
        let counters = self.read().await.ok();
        Sample {
            started_at,
            finished_at: Utc::now(),
            counters,
        }
    }

    async fn read(&self) -> Result<ReplayEgressCounterSnapshot> {
        let mut command = tokio::process::Command::new(&self.program);
        command.args(&self.arguments).kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output()).await??;
        ensure!(output.status.success(), "firewall counter reader failed");
        ensure!(
            output.stdout.len() <= 4096,
            "oversized firewall counter output"
        );
        serde_json::from_slice(&output.stdout).context("invalid firewall counter snapshot")
    }
}

pub fn difference(case_id: &str, before: Sample, after: Sample) -> ReplayEgressRejections {
    let rejected_packets = before
        .counters
        .as_ref()
        .zip(after.counters.as_ref())
        .and_then(|(before, after)| {
            if before.generation != after.generation {
                return None;
            }
            after
                .ipv4_packets
                .checked_sub(before.ipv4_packets)?
                .checked_add(after.ipv6_packets.checked_sub(before.ipv6_packets)?)
        });
    ReplayEgressRejections {
        case_id: case_id.to_string(),
        observed_from: before.started_at,
        observed_until: after.finished_at,
        rejected_packets,
        unavailable_reason: rejected_packets
            .is_none()
            .then(|| "counter_read_failed_or_rules_reset".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(generation: &str, v4: u64, v6: u64) -> Sample {
        Sample {
            started_at: Utc::now(),
            finished_at: Utc::now(),
            counters: Some(ReplayEgressCounterSnapshot {
                generation: generation.into(),
                ipv4_packets: v4,
                ipv6_packets: v6,
            }),
        }
    }
    #[test]
    fn counters_are_packet_deltas_and_resets_are_unknown() {
        assert_eq!(
            difference("case", sample("a", 10, 20), sample("a", 12, 23)).rejected_packets,
            Some(5)
        );
        assert_eq!(
            difference("case", sample("a", 10, 20), sample("a", 10, 20)).rejected_packets,
            Some(0)
        );
        assert_eq!(
            difference("case", sample("a", 10, 20), sample("b", 100, 100)).rejected_packets,
            None
        );
        assert_eq!(
            difference("case", sample("a", 10, 20), sample("a", 9, 22)).rejected_packets,
            None
        );
        let mut missing = sample("a", 10, 20);
        missing.counters = None;
        assert_eq!(
            difference("case", missing, sample("a", 11, 20)).rejected_packets,
            None
        );
    }
}
