//! Source-only Global preparation. No Case oracle, Target, CA, DNS or listener is involved.
use super::*;
use crate::protocols::replay::report::ReportView;
use std::sync::Arc;
use traffic_replay::report::{GlobalReportProjection, JoinedProjection, ReportRows, Row};

pub(crate) struct GlobalSource {
    pub native: native::Inventory,
    pub mysql: MysqlReplayState,
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
            mysql: Default::default(),
        };
        let mut targets = BTreeMap::new();
        let mut identities = HashMap::new();
        let reader = Arc::new(std::sync::Mutex::new(
            crate::dependency_index::RecordReader::new(8 * 1024 * 1024),
        ));
        crate::protocols::replay::source::global::load(
            path,
            ReplaySource::Startup,
            &mut source.mysql,
            &mut targets,
            &mut identities,
            rules,
            reader.clone(),
            &mut source.native,
        )
        .await?;
        if let Some(run) = crate::dependency_index::recording::root(path) {
            let process = run.join("indexes/process-scope.json");
            if process.is_file() {
                crate::protocols::replay::source::global::load(
                    &process,
                    ReplaySource::Process,
                    &mut source.mysql,
                    &mut targets,
                    &mut identities,
                    rules,
                    reader.clone(),
                    &mut source.native,
                )
                .await?;
            }
        }
        freeze(&mut source.mysql);
        source.native.freeze_global_report_layout();
        Ok(source)
    }
    pub fn retain_source_extensions(&self, _marker: &Path) -> Result<BTreeMap<String, Value>> {
        Ok(BTreeMap::new())
    }

    fn builtin_view(&self) -> ReportView<'_> {
        ReportView { mysql: &self.mysql }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn freeze(mysql: &mut MysqlReplayState) {
    mysql.freeze_global_report_layout();
}

impl GlobalReportProjection for GlobalSource {
    fn global_report_protocols(&self) -> Vec<String> {
        JoinedProjection::new(&self.builtin_view(), &self.native).global_report_protocols()
    }
    fn global_report_layout(&self, protocol: &str) -> Result<Vec<usize>> {
        JoinedProjection::new(&self.builtin_view(), &self.native).global_report_layout(protocol)
    }
    fn global_report_semantics(&self, protocol: &str) -> Option<String> {
        JoinedProjection::new(&self.builtin_view(), &self.native).global_report_semantics(protocol)
    }
    fn global_report_is_stable(&self, protocol: &str) -> bool {
        JoinedProjection::new(&self.builtin_view(), &self.native).global_report_is_stable(protocol)
    }
    fn visit_global_report(
        &self,
        protocol: &str,
        rows: ReportRows,
        visitor: &mut dyn FnMut(Row) -> Result<()>,
    ) -> Result<()> {
        JoinedProjection::new(&self.builtin_view(), &self.native)
            .visit_global_report(protocol, rows, visitor)
    }
}
