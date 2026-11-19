use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::model::*;

use crate::source::{FileStamp, RecordLocation, RecordStream, digest, scoped, store};

pub struct Builder {
    index: FileIndex,
    endpoints: BTreeSet<Endpoint>,
    hash: Sha256,
    offset: u64,
    scoped: bool,
    evidence: traffic_protocol::evidence::EvidenceRegistry,
    select_proof: fn(&Value) -> bool,
}

impl Builder {
    pub fn with_evidence(
        stamp: FileStamp,
        evidence: traffic_protocol::evidence::EvidenceRegistry,
        select_proof: fn(&Value) -> bool,
    ) -> Self {
        Self {
            evidence,
            select_proof,
            index: FileIndex {
                version: VERSION,
                stamp,
                sha256: String::new(),
                scope_membership_sha256: None,
                events: 0,
                endpoints: Vec::new(),
                metadata: Vec::new(),
                indexes: Default::default(),
                proof_records: Some(Vec::new()),
            },
            endpoints: BTreeSet::new(),
            hash: Sha256::new(),
            offset: 0,
            scoped: false,
        }
    }

    /// Observe a physical record location and its materialized semantic bytes.
    pub fn observe_at(
        &mut self,
        location: &RecordLocation,
        raw: &[u8],
        value: Option<&Value>,
    ) -> Result<()> {
        if self.offset != location.offset {
            self.scoped = true;
        }
        self.offset = location.offset + location.length;
        self.hash.update(raw);
        let Some(value) = value else {
            return Ok(());
        };
        self.index.events += 1;
        let line = location.line;
        if (self.select_proof)(value) {
            self.index
                .proof_records
                .as_mut()
                .expect("proof inventory")
                .push(ProofRecord {
                    location: location.clone(),
                    selector: self.evidence.proof_selector(value),
                });
        }
        let projection = self.evidence.lookup_projection(value)?;
        for endpoint in projection.endpoints {
            self.endpoints.insert(Endpoint {
                host: endpoint.host,
                port: endpoint.port,
                protocol: endpoint.protocol,
            });
        }
        for observation in projection.observations {
            self.index.metadata.push((line, observation));
        }
        for lookup in projection.lookups {
            self.index
                .indexes
                .entry(lookup.index)
                .or_default()
                .push(IndexedRecord {
                    location: location.clone(),
                    key: lookup.key.unwrap_or_else(|| location.sha256.clone()),
                    connection_id: lookup.connection,
                    summary: lookup.summary,
                });
        }
        Ok(())
    }

    pub fn set_scoped(&mut self) {
        self.scoped = true;
    }

    pub fn observe(&mut self, line: usize, raw: &[u8], value: Option<&Value>) -> Result<()> {
        let location = RecordLocation {
            line,
            offset: self.offset,
            length: raw.len() as u64,
            sha256: digest(raw),
        };
        self.observe_at(&location, raw, value)
    }

    pub fn finish(mut self) -> Result<FileIndex> {
        ensure!(
            self.scoped || self.offset == self.index.stamp.size,
            "dependency file changed while building index"
        );
        self.index.sha256 = format!("{:x}", self.hash.finalize());
        self.index.endpoints = self.endpoints.into_iter().collect();
        Ok(self.index)
    }
}

pub fn build_file(
    path: &Path,
    cancelled: &std::sync::atomic::AtomicBool,
    evidence: &traffic_protocol::evidence::EvidenceRegistry,
    select_proof: fn(&Value) -> bool,
) -> Result<FileIndex> {
    let stamp = FileStamp::read(path)?;
    let mut builder = Builder::with_evidence(stamp.clone(), evidence.clone(), select_proof);
    let mut input = RecordStream::open(path)?;
    if input.uses_locations() {
        builder.set_scoped();
    }
    while let Some((location, raw)) = input.next()? {
        store::check_cancelled(cancelled)?;
        let line = location.line;
        let value = if raw.iter().all(u8::is_ascii_whitespace) {
            None
        } else {
            Some(serde_json::from_slice::<Value>(raw).with_context(|| {
                format!("invalid dependency evidence {} line {line}", path.display())
            })?)
        };
        builder.observe_at(&location, raw, value.as_ref())?;
    }
    scoped::validate_stamp(path, &stamp)?;
    builder.finish()
}
