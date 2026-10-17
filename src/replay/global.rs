//! Global evidence is traversed with a bounded pipeline, independently of case loading.
use super::*;
use crate::dependency_index::{Paged, RecordReader, RecordRef, RecordSource};

type StreamItem = (DependencyRecord, RecordRef, Option<(usize, bool)>);
type StreamBatch = Vec<StreamItem>;

#[derive(Clone, Copy)]
enum Phase {
    Metadata,
    Exchanges,
}

impl Phase {
    fn accepts(self, record: &Value) -> Result<bool> {
        let kind = record["event_type"]
            .as_str()
            .context("Global index record lacks an event type")?;
        Ok(match self {
            Self::Metadata => matches!(
                kind,
                "mysql_connection"
                    | "mysql_exchange"
                    | "redis_pub_sub_push"
                    | "redis_connection"
                    | "memcached_connection"
                    | "kafka_connection"
                    | "motan_connection"
                    | "proxy_error"
            ),
            Self::Exchanges => matches!(
                kind,
                "tcp_gateway_connection"
                    | "http_exchange"
                    | "redis_exchange"
                    | "memcached_exchange"
                    | "motan_exchange"
                    | "kafka_produce"
                    | "kafka_fetch"
                    | "kafka_delivery"
            ),
        })
    }
}

fn stream(
    inventory: Paged<crate::dependency_index::global::GlobalEntry>,
    source: Arc<RecordSource>,
    phase: Phase,
) -> (
    tokio::sync::mpsc::Receiver<StreamBatch>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::task::spawn_blocking(move || {
        for page in 0..inventory.pages() {
            let mut batch = Vec::new();
            for entry in inventory.read_page(page)? {
                // The index already validated the complete original records.
                // Decode only the types registered in this phase, in source order.
                if !phase.accepts(&entry.record)? {
                    continue;
                }
                let reference = source.reference(entry.location);
                // RPC/unsafe notification evidence retains its original full codec validation.
                let record = if entry.record["event_type"] == "redis_pub_sub_push" {
                    reference.load()?
                } else {
                    serde_json::from_value(entry.record)?
                };
                batch.push((record, reference, entry.mysql_row_shape));
            }
            // A page is already bounded to 256 metadata records / 64 KiB,
            // except for a single oversized record. Only one batch is queued.
            if !batch.is_empty() && tx.blocking_send(batch).is_err() {
                return Ok(());
            }
        }
        source.validate()?;
        Ok(())
    });
    (rx, task)
}

async fn consume(
    mut input: tokio::sync::mpsc::Receiver<StreamBatch>,
    task: tokio::task::JoinHandle<Result<()>>,
    context: &'static str,
    mut register: impl FnMut(StreamItem) -> Result<()>,
) -> Result<()> {
    let registration = async {
        while let Some(batch) = input.recv().await {
            for item in batch {
                register(item)?;
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Registration errors close the bounded channel before joining the producer;
    // no blocked/detached indexing task survives an aborted phase.
    drop(input);
    let traversal = task.await.context(context);
    registration?;
    traversal??;
    Ok(())
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
    let (input, task) = stream(records.clone(), source.clone(), Phase::Metadata);
    // Subscription/RPC anchors must be known before any exchange is linked.
    consume(
        input,
        task,
        "Global metadata traversal failed",
        |(record, reference, row_shape)| {
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
            Ok(())
        },
    )
    .await?;
    redis.pubsub.finish_indexed()?;
    let (input, task) = stream(records, source, Phase::Exchanges);
    consume(
        input,
        task,
        "Global exchange traversal failed",
        |(record, reference, _)| {
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
            Ok(())
        },
    )
    .await?;
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

#[cfg(test)]
mod tests;
