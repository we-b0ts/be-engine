//! Protocol-owned stored evidence formats used by shared report paging and publication.
use crate::ProtocolId;
use anyhow::{Result, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub mod diagnostics;
mod empty;
pub mod findings;
pub mod validation;

pub trait ReportSection: Send + Sync {
    fn count(&self) -> Result<usize>;
    fn read(
        &self,
        report: &Path,
        offset: usize,
        limit: usize,
        items: &mut Vec<Value>,
    ) -> Result<()>;
    fn stage(&self, source: &Path, destination: &Path) -> Result<Value>;
}

pub trait ReportCodec: Send + Sync {
    fn validate_legacy_session(&self, _report: &Value, _protocol: &str) -> Result<Option<usize>> {
        Ok(None)
    }
    fn diagnostics(&self) -> &dyn diagnostics::DiagnosticSchema {
        &diagnostics::STANDARD
    }
    fn decode(&self, _report: &Path, _value: &Value) -> Result<Option<Box<dyn ReportSection>>> {
        Ok(None)
    }
    fn decode_extensions(
        &self,
        _report: &Path,
        fields: &BTreeMap<String, Value>,
    ) -> Result<Box<dyn ReportSection>> {
        empty::decode(fields)
    }
    fn reclassified_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report["dependency_protocols"][protocol]["unused_global"]
    }
    fn unused_case_rows<'a>(&self, report: &'a Value, protocol: &str) -> &'a Value {
        &report["dependency_protocols"][protocol]["unused_case"]
    }
    fn supports_source_occurrences(&self) -> bool {
        true
    }
    fn requires_source_exchange_id(&self, _row: &Value) -> bool {
        false
    }
}

#[derive(Clone, Default)]
pub struct CodecRegistry {
    codecs: BTreeMap<ProtocolId, Arc<dyn ReportCodec>>,
}
impl std::fmt::Debug for CodecRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_list().entries(self.codecs.keys()).finish()
    }
}
impl CodecRegistry {
    pub fn validate_legacy_sessions(&self, report: &Value) -> Result<BTreeMap<String, usize>> {
        let mut unused = BTreeMap::new();
        for (protocol, codec) in self.iter() {
            if let Some(count) = codec.validate_legacy_session(report, protocol.as_str())? {
                unused.insert(protocol.as_str().into(), count);
            }
        }
        Ok(unused)
    }
    pub fn iter(&self) -> impl Iterator<Item = (ProtocolId, &dyn ReportCodec)> {
        self.codecs
            .iter()
            .map(|(protocol, codec)| (*protocol, codec.as_ref()))
    }
    pub fn register(&mut self, protocol: ProtocolId, codec: Arc<dyn ReportCodec>) -> Result<()> {
        ensure!(
            !protocol.as_str().is_empty() && !self.codecs.contains_key(&protocol),
            "report codec identity is empty or already registered"
        );
        self.codecs.insert(protocol, codec);
        Ok(())
    }
    pub fn codec(&self, protocol: &str) -> Option<Arc<dyn ReportCodec>> {
        self.codecs
            .iter()
            .find(|(id, _)| id.as_str() == protocol)
            .map(|(_, codec)| codec.clone())
    }

    pub(crate) fn replace(
        &mut self,
        old_name: &str,
        name: &'static str,
        codec: Option<Arc<dyn ReportCodec>>,
    ) -> Result<()> {
        let mut replacement = self.clone();
        replacement.codecs.retain(|id, _| id.as_str() != old_name);
        if let Some(codec) = codec {
            replacement.register(ProtocolId::new(name), codec)?;
        }
        *self = replacement;
        Ok(())
    }

    pub fn diagnose(&self, facts: &Value) -> Result<diagnostics::Diagnosis> {
        let mut diagnosis = diagnostics::Diagnosis::default();
        let findings = findings::representative_findings(facts);
        if !findings.is_empty() {
            diagnosis
                .details
                .insert("policy_findings".into(), Value::Array(findings));
            diagnosis.details.insert(
                "policy_findings_scope".into(),
                Value::String("cluster_representatives".into()),
            );
        }
        for (_, codec) in self.iter() {
            let native = codec.diagnostics().diagnose(facts);
            for (name, detail) in native.details {
                ensure!(
                    !diagnosis.details.contains_key(&name),
                    "native diagnosis would replace an existing fact {name:?}"
                );
                diagnosis.details.insert(name, detail);
            }
            diagnosis.limitations.extend(native.limitations);
            diagnosis.next_steps.extend(native.next_steps);
        }
        Ok(diagnosis)
    }

    pub fn has_value_difference(&self, facts: &Value) -> bool {
        self.iter()
            .any(|(_, codec)| codec.diagnostics().has_value_difference(facts))
    }
}
