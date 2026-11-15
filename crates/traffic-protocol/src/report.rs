//! Protocol-owned stored evidence formats used by shared report paging and publication.
use crate::ProtocolId;
use anyhow::{Result, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub mod diagnostics;

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
    fn diagnostics(&self) -> &dyn diagnostics::DiagnosticSchema {
        &diagnostics::STANDARD
    }
    fn decode(&self, report: &Path, value: &Value) -> Result<Option<Box<dyn ReportSection>>>;
    fn decode_extensions(
        &self,
        report: &Path,
        fields: &BTreeMap<String, Value>,
    ) -> Result<Box<dyn ReportSection>>;
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
}
