//! Source-only Global preparation. No Case oracle, Target, CA, DNS or listener is involved.
use super::*;
use crate::protocols::replay::report::ReportView;
use crate::replay::http::HttpReplayEvents;
use std::sync::Arc;
use traffic_replay::report::{GlobalReportProjection, JoinedProjection, ReportRows, Row};

pub(crate) struct GlobalSource {
    pub native: native::Inventory,
    pub mysql: MysqlReplayState,
    pub http: Vec<http::ReplayHttpExchange>,
    pub http_events: HttpReplayEvents,
    pub redis: redis::RedisReplayState,
    pub memcached: memcached::MemcachedReplayState,
    pub kafka: kafka::KafkaReplayState,
    pub motan: motan::MotanReplayState,
}

impl GlobalSource {
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
            http: vec![],
            http_events: Default::default(),
            redis: Default::default(),
            memcached: Default::default(),
            kafka: Default::default(),
            motan: Default::default(),
        };
        let mut blackholes = vec![];
        let mut targets = BTreeMap::new();
        let mut identities = HashMap::new();
        let reader = Arc::new(std::sync::Mutex::new(
            crate::dependency_index::RecordReader::new(8 * 1024 * 1024),
        ));
        crate::protocols::replay::source::global::load(
            path,
            ReplaySource::Startup,
            &mut source.mysql,
            &mut source.http,
            &mut blackholes,
            &mut source.redis,
            &mut source.memcached,
            &mut source.kafka,
            &mut source.motan,
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
                    &mut source.http,
                    &mut blackholes,
                    &mut source.redis,
                    &mut source.memcached,
                    &mut source.kafka,
                    &mut source.motan,
                    &mut targets,
                    &mut identities,
                    rules,
                    reader.clone(),
                    &mut source.native,
                )
                .await?;
            }
        }
        freeze(
            &mut source.mysql,
            &mut source.http_events,
            source.http.len(),
            &mut source.redis,
            &mut source.memcached,
            &mut source.kafka,
            &mut source.motan,
        );
        source.native.freeze_global_report_layout();
        // Subscription mirrors are native confirmation proofs. Legacy captures
        // may resolve their native subscription record from Case dependency files;
        // expected-response files and Case assertion identities are never read.
        let physical = crate::dependency_index::scoped::resolve(path)?.path;
        let root = physical
            .parent()
            .context("run-owned Source has no parent")?
            .to_owned();
        let rules = rules.to_vec();
        tokio::task::spawn_blocking(move || {
            source
                .redis
                .resolve_pubsub_subscriptions(&root, &mut targets, &rules, reader)?;
            Ok(source)
        })
        .await
        .context("Source Global subscription preparation task failed")?
    }
    pub fn retain_source_extensions(&self, marker: &Path) -> Result<BTreeMap<String, Value>> {
        let session = self.redis.global_notification_evidence()?;
        if session.lanes.is_empty() {
            return Ok(BTreeMap::new());
        }
        let reference = crate::protocols::replay::report::redis::shared::retain_portable(
            marker,
            &session.lanes,
        )?;
        Ok(BTreeMap::from([(
            "notifications".into(),
            serde_json::to_value(reference)?,
        )]))
    }
    fn builtin_view(&self) -> ReportView<'_> {
        ReportView {
            mysql: &self.mysql,
            http: &self.http,
            http_events: &self.http_events,
            redis: &self.redis,
            memcached: &self.memcached,
            kafka: &self.kafka,
            motan: &self.motan,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn freeze(
    mysql: &mut MysqlReplayState,
    http: &mut HttpReplayEvents,
    http_len: usize,
    redis: &mut redis::RedisReplayState,
    memcached: &mut memcached::MemcachedReplayState,
    kafka: &mut kafka::KafkaReplayState,
    motan: &mut motan::MotanReplayState,
) {
    mysql.freeze_global_report_layout();
    http.global_report.freeze_layout(vec![http_len]);
    redis.freeze_global_report_layout();
    memcached.freeze_global_report_layout();
    kafka.freeze_global_report_layout();
    motan.freeze_global_report_layout();
}

impl GlobalSource {
    pub fn view(&self) -> &Self {
        self
    }
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
