//! Global evidence is traversed with a bounded pipeline, independently of case loading.
use super::*;
use crate::dependency_index::{Paged, RecordReader, RecordRef, RecordSource};

type StreamItem = (DependencyRecord, RecordRef, Option<(usize, bool)>);

fn stream(
    inventory: Paged<crate::dependency_index::global::GlobalEntry>,
    source: Arc<RecordSource>,
) -> (
    tokio::sync::mpsc::Receiver<StreamItem>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::task::spawn_blocking(move || {
        for page in 0..inventory.pages() {
            for entry in inventory.read_page(page)? {
                let reference = source.reference(entry.location);
                // RPC/unsafe notification evidence retains its original full codec validation.
                let record = if entry.record["event_type"] == "redis_pub_sub_push" {
                    reference.load()?
                } else {
                    serde_json::from_value(entry.record)?
                };
                if tx
                    .blocking_send((record, reference, entry.mysql_row_shape))
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
        source.validate()?;
        Ok(())
    });
    (rx, task)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn load(
    path: &Path,
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
) -> Result<()> {
    let source_path = path.to_owned();
    let (index, root) = tokio::task::spawn_blocking(move || {
        crate::dependency_index::global::load_global_index(&source_path, validate_index_record)
    })
    .await
    .context("Global index preparation failed")??;
    let source = RecordSource::new(path, index.stamp.clone(), reader);
    redis
        .pubsub
        .restore_indexed(index.notifications.clone(), &root, source.clone())?;
    let records = crate::dependency_index::global::global_records(&index, &root)?;
    let mut sql = Vec::new();
    let (mut input, task) = stream(records.clone(), source.clone());
    // Subscription/RPC anchors must be known before any exchange is linked.
    while let Some((record, reference, row_shape)) = input.recv().await {
        match record {
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
                redis.pubsub.register_indexed(*push, reference)?
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
        }
    }
    task.await.context("Global metadata traversal failed")??;
    redis.pubsub.finish_indexed()?;
    let (mut input, task) = stream(records, source);
    while let Some((record, reference, _)) = input.recv().await {
        match record {
            DependencyRecord::TcpGatewayConnection(record) => {
                http::register_tcp_connection_blackhole(
                    *record,
                    ReplaySource::Global,
                    None,
                    blackholes,
                    targets,
                )?
            }
            DependencyRecord::HttpExchange(mut record) => {
                record.decrypt_request_headers(path)?;
                http::register_global_exchange(*record, reference, http, targets)?;
            }
            DependencyRecord::RedisExchange(record) => {
                redis.register_global_exchange(*record, reference, targets, rules)?
            }
            DependencyRecord::MemcachedExchange(record) => {
                memcached.register_global_exchange(*record, reference, targets)?
            }
            DependencyRecord::MotanExchange(record) => {
                motan.register_global_exchange(*record, reference, targets)?
            }
            DependencyRecord::KafkaProduce(record) => {
                kafka.register_global_produce(*record, reference, targets)?
            }
            DependencyRecord::KafkaFetch(record) => {
                kafka.register_fetch(*record, ReplaySource::Global, None, targets)?
            }
            DependencyRecord::KafkaDelivery(record) => {
                kafka.register_global_delivery(*record, reference, targets)?
            }
            _ => {}
        }
    }
    task.await.context("Global exchange traversal failed")??;
    register_dependency_records(
        path,
        sql,
        &BTreeSet::new(),
        ReplaySource::Global,
        None,
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
    )?;
    Ok(())
}
