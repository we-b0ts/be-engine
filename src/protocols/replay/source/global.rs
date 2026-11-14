//! Native Global preparation and record projection supplied to bounded traversal.
use super::*;
use crate::dependency_index::global::{GlobalEntry, GlobalIndex};
use crate::dependency_index::{RecordReader, RecordRef, RecordSource};
use crate::replay::global::{GlobalProjection, GlobalRegistrar, Phase};
use std::sync::Arc;

mod notifications;
pub(crate) use notifications::load as load_unattributed_notifications;

pub(crate) struct Records;
impl GlobalProjection for Records {
    type Item = (DependencyRecord, RecordRef, Option<(usize, bool)>);
    fn validate(record: &Value) -> Result<()> {
        validate_index_record(record)
    }
    fn accepts(phase: Phase, record: &Value) -> Result<bool> {
        let kind = record["event_type"]
            .as_str()
            .context("Global index record lacks an event type")?;
        let metadata = matches!(
            kind,
            "mysql_connection"
                | "mysql_exchange"
                | "redis_pub_sub_push"
                | "redis_connection"
                | "memcached_connection"
                | "kafka_connection"
                | "motan_connection"
                | "proxy_error"
        );
        Ok(match phase {
            Phase::Metadata => metadata,
            Phase::Exchanges => !metadata,
        })
    }
    fn decode(entry: GlobalEntry, source: &Arc<RecordSource>) -> Result<Self::Item> {
        let reference = source.reference(entry.location);
        // Notification codecs validate original frames through their authenticated reference.
        let record = if entry.record["event_type"] == "redis_pub_sub_push" {
            reference.load()?
        } else {
            serde_json::from_value(entry.record)?
        };
        Ok((record, reference, entry.mysql_row_shape))
    }
}

struct Registration<'a> {
    path: &'a Path,
    source_kind: ReplaySource,
    mysql: &'a mut MysqlReplayState,
    http: &'a mut Vec<http::ReplayHttpExchange>,
    blackholes: &'a mut Vec<http::ReplayHttpBlackhole>,
    redis: &'a mut redis::RedisReplayState,
    memcached: &'a mut memcached::MemcachedReplayState,
    kafka: &'a mut kafka::KafkaReplayState,
    motan: &'a mut motan::MotanReplayState,
    targets: &'a mut BTreeMap<TargetKey, ReplayTarget>,
    identities: &'a mut HashMap<Uuid, MysqlDependencyIdentity>,
    rules: &'a [crate::BackgroundDependencyRuleConfig],
    native: &'a mut native::Inventory,
    sql: Vec<(usize, DependencyRecord)>,
}

impl GlobalRegistrar for Registration<'_> {
    type Projection = Records;
    fn prepare(
        &mut self,
        index: &GlobalIndex,
        root: &Path,
        source: Arc<RecordSource>,
    ) -> Result<()> {
        self.redis.pubsub.restore_indexed(
            index.notifications.clone(),
            root,
            source,
            self.source_kind,
        )
    }
    fn register(&mut self, phase: Phase, item: <Records as GlobalProjection>::Item) -> Result<()> {
        let (record, reference, row_shape) = item;
        let source_kind = self.source_kind;
        let Self {
            path,
            mysql: _,
            http,
            blackholes,
            redis,
            memcached,
            kafka,
            motan,
            targets,
            identities,
            rules,
            native,
            sql,
            ..
        } = self;
        match phase {
            Phase::Metadata => match record {
                DependencyRecord::MysqlConnection(connection) => {
                    if let Some(identity) = identity_from_connection(&connection) {
                        register_replay_target(targets, &identity.target, ReplayProtocol::Mysql)?;
                        identities.insert(connection.id, identity);
                    }
                }
                DependencyRecord::MysqlExchange(mut exchange) => {
                    let line = reference.location.line;
                    exchange.response.detach(reference);
                    exchange.response.row_shape = row_shape.or(exchange.response.row_shape);
                    sql.push((line, DependencyRecord::MysqlExchange(exchange)));
                }
                DependencyRecord::RedisPubSubPush(push) => {
                    redis
                        .pubsub
                        .register_indexed(*push, reference, source_kind)?
                }
                DependencyRecord::RedisConnection(connection) => {
                    redis.register_connection(*connection, targets)?
                }
                DependencyRecord::MemcachedConnection(connection) => {
                    memcached.register_connection(*connection, targets)?
                }
                DependencyRecord::KafkaConnection(connection) => {
                    kafka.register_connection(*connection, targets)?
                }
                DependencyRecord::MotanConnection(connection) => {
                    motan.register_connection(*connection, targets)?
                }
                DependencyRecord::ProxyError(error) => {
                    redis::RedisReplayState::reject_proxy_error(&error)?;
                    memcached::MemcachedReplayState::reject_proxy_error(&error)?;
                    motan::MotanReplayState::reject_proxy_error(&error)?;
                    ensure!(
                        error.protocol != "kafka",
                        "unsafe Kafka dependency proxy error: {}",
                        error.error
                    );
                }
                _ => {}
            },
            Phase::Exchanges => match record {
                DependencyRecord::Native(record) => {
                    native.register(
                        &record,
                        source_kind,
                        None,
                        reference.location.line,
                        targets,
                    )?;
                }
                DependencyRecord::TcpGatewayConnection(record) => {
                    http::register_tcp_connection_blackhole(
                        *record,
                        source_kind,
                        None,
                        blackholes,
                        targets,
                    )?
                }
                DependencyRecord::HttpExchange(mut record) => {
                    record.decrypt_request_headers(path)?;
                    http::register_global_exchange(
                        *record,
                        reference,
                        http,
                        targets,
                        rules,
                        source_kind,
                    )?;
                }
                DependencyRecord::RedisExchange(record) => redis.register_global_exchange(
                    *record,
                    source_kind,
                    reference,
                    targets,
                    rules,
                )?,
                DependencyRecord::MemcachedExchange(record) => {
                    memcached.register_global_exchange(*record, source_kind, reference, targets)?
                }
                DependencyRecord::MotanExchange(record) => {
                    motan.register_global_exchange(*record, source_kind, reference, targets)?
                }
                DependencyRecord::KafkaProduce(record) => {
                    kafka.register_global_produce(*record, source_kind, reference, targets)?
                }
                DependencyRecord::KafkaFetch(record) => {
                    kafka.register_fetch(*record, source_kind, None, targets)?
                }
                DependencyRecord::KafkaDelivery(record) => {
                    kafka.register_global_delivery(*record, source_kind, reference, targets)?
                }
                _ => {}
            },
        }
        Ok(())
    }
    fn complete(&mut self, phase: Phase) -> Result<()> {
        match phase {
            Phase::Metadata => self.redis.pubsub.finish_indexed(),
            Phase::Exchanges => register_dependency_records(
                self.path,
                std::mem::take(&mut self.sql),
                &BTreeSet::new(),
                self.source_kind,
                None,
                self.mysql,
                self.http,
                self.blackholes,
                self.redis,
                self.memcached,
                self.kafka,
                self.motan,
                self.targets,
                self.identities,
                self.rules,
                &BTreeSet::new(),
                self.native,
            ),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn load(
    path: &Path,
    source_kind: ReplaySource,
    mysql: &mut MysqlReplayState,
    http: &mut Vec<http::ReplayHttpExchange>,
    blackholes: &mut Vec<http::ReplayHttpBlackhole>,
    redis: &mut redis::RedisReplayState,
    memcached: &mut memcached::MemcachedReplayState,
    kafka: &mut kafka::KafkaReplayState,
    motan: &mut motan::MotanReplayState,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    identities: &mut HashMap<Uuid, MysqlDependencyIdentity>,
    rules: &[crate::BackgroundDependencyRuleConfig],
    reader: Arc<std::sync::Mutex<RecordReader>>,
    native: &mut native::Inventory,
) -> Result<()> {
    replay::global::load(
        path,
        reader,
        &mut Registration {
            path,
            source_kind,
            mysql,
            http,
            blackholes,
            redis,
            memcached,
            kafka,
            motan,
            targets,
            identities,
            rules,
            native,
            sql: Vec::new(),
        },
    )
    .await
}
