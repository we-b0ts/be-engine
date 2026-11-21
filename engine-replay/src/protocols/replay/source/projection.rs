//! Source-only Global preparation. No Case oracle, Target, CA, DNS or listener is involved.
use super::*;
use std::sync::Arc;
use traffic_replay::report::{GlobalReportProjection, ReportRows, Row};

pub struct GlobalSource {
    pub native: native::Inventory,
}

impl GlobalSource {
    #[cfg(test)]
    pub async fn load(
        path: &Path,
        rules: &[crate::BackgroundDependencyRuleConfig],
    ) -> Result<Self> {
        Self::load_with_providers(path, rules, crate::protocols::default_providers()).await
    }
    pub async fn load_with_providers(
        path: &Path,
        rules: &[crate::BackgroundDependencyRuleConfig],
        providers: Arc<crate::protocols::DependencyProviders>,
    ) -> Result<Self> {
        let mut source = Self {
            native: native::Inventory::new(providers),
        };
        let mut targets = BTreeMap::new();
        let reader = Arc::new(std::sync::Mutex::new(
            crate::dependency_index::RecordReader::new(8 * 1024 * 1024),
        ));
        crate::protocols::replay::source::global::load(
            path,
            ReplaySource::Startup,
            &mut targets,
            rules,
            reader.clone(),
            &mut source.native,
        )
        .await?;
        if let Some(run) = crate::dependency_index::recording::root(path) {
            let process = run.join("indexes/process-scope.json");
            if crate::dependency_index::scoped::exists(&process) {
                crate::protocols::replay::source::global::load(
                    &process,
                    ReplaySource::Process,
                    &mut targets,
                    rules,
                    reader.clone(),
                    &mut source.native,
                )
                .await?;
            }
        }
        source.native.freeze_global_report_layout();
        Ok(source)
    }
    pub fn retain_source_extensions(&self, _marker: &Path) -> Result<BTreeMap<String, Value>> {
        Ok(BTreeMap::new())
    }
}

impl GlobalReportProjection for GlobalSource {
    fn global_report_protocols(&self) -> Vec<String> {
        self.native.global_report_protocols()
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        self.native.global_report_layout(protocol)
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        self.native.global_report_semantics(protocol)
    }
    fn global_report_is_stable(&self, protocol: &str) -> bool {
        self.native.global_report_is_stable(protocol)
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        self.native.visit_global_report(protocol, rows, visitor)
    }
}
