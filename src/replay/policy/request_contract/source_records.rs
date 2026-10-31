//! Bind native witness observations to their original semantic JSONL locations.
use super::*;
use crate::{
    dependency_index::{FileStamp, RecordLocation},
    policy_evidence::{SourceIdentity, SourceRecord},
};

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct IdentityFacts {
    event_type: Value,
    id: Value,
    connection_id: Value,
    sequence: Value,
    query_sequence: Value,
    capture: Option<crate::dependency::observation::CaptureMetadata>,
}
impl IdentityFacts {
    fn identity(&self, case: &str) -> SourceIdentity {
        let http = self.event_type == "http_exchange";
        SourceIdentity {
            case_id: case.into(),
            exchange_id: if http {
                self.id.as_str().map(str::to_owned)
            } else {
                None
            },
            connection_id: if http {
                None
            } else {
                self.connection_id.as_str().map(str::to_owned)
            },
            sequence: if http {
                None
            } else if self.event_type == "mysql_exchange" {
                self.query_sequence.as_u64()
            } else {
                self.sequence.as_u64()
            },
        }
    }
}

impl RequestContracts {
    /// Register immutable Source context without admitting a runnable Target case.
    pub(in crate::replay) fn register_source_origin(
        &self,
        case: &str,
        directory: &Path,
    ) -> Result<()> {
        if self
            .state
            .lock()
            .expect("request contracts")
            .cases
            .contains_key(case)
        {
            return Ok(());
        }
        let raw = std::fs::read(directory.join("request.json"))?;
        let request: Value = serde_json::from_slice(&raw)?;
        let anchor = CaseAnchor::from_request(directory, &request, &self.rules);
        let mut state = self.state.lock().expect("request contracts");
        state
            .primary_protocols
            .insert(case.into(), case_plan::input_protocol(&raw));
        state
            .source_request_digests
            .insert(case.into(), crate::policy_evidence::digest(&raw));
        state.cases.entry(case.into()).or_insert(anchor);
        Ok(())
    }

    pub(super) fn register_source_records(&self, case: &str, bytes: &[u8]) -> Result<()> {
        let Some(store) = &self.witnesses else {
            return Ok(());
        };
        let path = self.anchor(case)?.dependencies_path;
        if !crate::dependency_index::scoped::exists(&path) {
            return Ok(());
        }
        let stamp = FileStamp::read(&path)?;
        let source = crate::dependency_index::scoped::resolve(&path)?;
        ensure!(
            crate::dependency_index::scoped::view_path(&path).is_some()
                || stamp.size == bytes.len() as u64,
            "Source dependency bytes differ from their immutable file"
        );
        let register = |facts: IdentityFacts, location: RecordLocation| -> Result<()> {
            if facts
                .capture
                .as_ref()
                .is_some_and(|capture| capture.owner_kind() != "case")
            {
                return Ok(());
            }
            let protocol = match facts.event_type.as_str() {
                Some("mysql_exchange") => crate::policy::Protocol::Mysql,
                Some("redis_exchange") => crate::policy::Protocol::Redis,
                Some("http_exchange") => crate::policy::Protocol::Http,
                Some("memcached_exchange") => crate::policy::Protocol::Memcached,
                _ => return Ok(()),
            };
            let id = facts.identity(case);
            if id.exchange_id.is_some() || id.connection_id.is_some() && id.sequence.is_some() {
                store.register_source_record(
                    &id,
                    protocol,
                    SourceRecord::from_source(&source, stamp.clone(), location),
                )?;
            }
            Ok(())
        };
        let index = crate::dependency_index::load_file(&path)?;
        ensure!(
            index.stamp == stamp,
            "Source dependency file changed during reference preparation"
        );
        if let Some(records) = index.proof_records {
            for record in records {
                register(serde_json::from_value(record.selector)?, record.location)?;
            }
            return Ok(());
        }
        let mut offset = 0;
        for (line, raw) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
            if !raw.iter().all(u8::is_ascii_whitespace) {
                // IgnoredAny validates the remaining JSON without allocating rows.
                register(
                    serde_json::from_slice(raw)?,
                    RecordLocation {
                        line: line + 1,
                        offset,
                        length: raw.len() as u64,
                        sha256: crate::policy_evidence::digest(raw)
                            .trim_start_matches("sha256:")
                            .into(),
                    },
                )?;
            }
            offset += raw.len() as u64;
        }
        Ok(())
    }
}
