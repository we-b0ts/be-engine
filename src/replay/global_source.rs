//! Source-only Global preparation. No Case oracle, Target, CA, DNS or listener is involved.
use super::*;
use report::global_evidence::regular::Row;

pub(super) struct GlobalSource {
    pub mysql: MysqlReplayState,
    pub http: Vec<http::ReplayHttpExchange>,
    pub http_events: http::HttpReplayEvents,
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
        let mut source = Self {
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
        global::load(
            path,
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
        )
        .await?;
        freeze(
            &mut source.mysql,
            &mut source.http_events,
            source.http.len(),
            &mut source.redis,
            &mut source.memcached,
            &mut source.kafka,
            &mut source.motan,
        );
        // Subscription mirrors are native confirmation proofs. Legacy captures
        // may resolve their native subscription record from Case dependency files;
        // expected-response files and Case assertion identities are never read.
        let root = path
            .parent()
            .context("Global Source has no parent")?
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
    pub fn view(&self) -> ProjectionView<'_> {
        ProjectionView {
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
pub(super) fn freeze(
    mysql: &mut MysqlReplayState,
    http: &mut http::HttpReplayEvents,
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

pub(super) struct ProjectionView<'a> {
    pub mysql: &'a MysqlReplayState,
    pub http: &'a [http::ReplayHttpExchange],
    pub http_events: &'a http::HttpReplayEvents,
    pub redis: &'a redis::RedisReplayState,
    pub memcached: &'a memcached::MemcachedReplayState,
    pub kafka: &'a kafka::KafkaReplayState,
    pub motan: &'a motan::MotanReplayState,
}
impl<'a> From<&'a ReplayState> for ProjectionView<'a> {
    fn from(state: &'a ReplayState) -> Self {
        Self {
            mysql: &state.mysql,
            http: &state.http_exchanges,
            http_events: &state.http_events,
            redis: &state.redis,
            memcached: &state.memcached,
            kafka: &state.kafka,
            motan: &state.motan,
        }
    }
}
impl ProjectionView<'_> {
    pub fn layout(&self, protocol: &str) -> Result<Vec<usize>> {
        Ok(match protocol {
            "mysql" => self.mysql.global_report_usage().layout().to_vec(),
            "http" => self.http_events.global_report.layout().to_vec(),
            "redis" => self.redis.global_report_layout(),
            "memcached" => self.memcached.global_report_usage().layout().to_vec(),
            "kafka" => self.kafka.global_report_usage().layout().to_vec(),
            "motan" => self.motan.global_report_usage().layout().to_vec(),
            _ => anyhow::bail!("unknown Global projection protocol"),
        })
    }
    pub fn visit(&self, protocol: &str, visitor: &mut dyn FnMut(Row) -> Result<()>) -> Result<()> {
        match protocol {
            "mysql" => self.mysql.visit_global_report_range(false, visitor),
            "http" => http::visit_global_report_rows(
                self.http,
                &self.http_events.global_report,
                false,
                visitor,
            ),
            "redis" => self.redis.visit_global_report_rows(visitor),
            "memcached" => self.memcached.visit_global_report_rows(visitor),
            "kafka" => self.kafka.visit_global_report_rows(visitor),
            "motan" => self.motan.visit_global_report_rows(visitor),
            _ => anyhow::bail!("unknown Global projection protocol"),
        }
    }
}
