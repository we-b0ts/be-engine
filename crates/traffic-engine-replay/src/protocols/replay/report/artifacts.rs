//! Public artifact queries bind the application registry to shared report storage.
use crate::replay::{GlobalDependencyPage, report::global_evidence};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub fn read_global_dependency_page(
    report: &Path,
    protocol: &str,
    offset: usize,
    limit: usize,
) -> Result<GlobalDependencyPage> {
    let providers = crate::protocols::default_providers();
    global_evidence::read_page(report, protocol, offset, limit, providers.report_codecs())
}

pub fn stage_global_evidence(source: &Path, destination: &Path) -> Result<Option<Value>> {
    let providers = crate::protocols::default_providers();
    global_evidence::stage(source, destination, providers.report_codecs())
}
