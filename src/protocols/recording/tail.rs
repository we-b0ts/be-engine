//! Native tail references and Source-stop observations projected into shared capture lifecycle.
use super::events::RecorderEvent;
use crate::active_case::{ActiveCaseRegistry, DependencyTargets};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub(crate) enum NativeReference {
    Connect { event_id: Uuid },
    Http { exchange_id: Uuid },
    Mysql { connection_id: Uuid, sequence: u64 },
    Redis { connection_id: Uuid, sequence: u64 },
    RedisRpcPush { connection_id: Uuid, sequence: u64 },
    Memcached { connection_id: Uuid, sequence: u64 },
    Motan { connection_id: Uuid, sequence: u64 },
    KafkaProduce { connection_id: Uuid, sequence: u64 },
    KafkaFetch { connection_id: Uuid, sequence: u64 },
    KafkaDelivery { connection_id: Uuid, sequence: u64 },
}

impl NativeReference {
    pub(crate) fn for_event(event: &RecorderEvent) -> Option<Self> {
        if !crate::recorder::should_append_case_dependency(event) {
            return None;
        }
        Some(match event {
            RecorderEvent::DependencyConnectFailure(event) => Self::Connect { event_id: event.id },
            RecorderEvent::HttpExchange(exchange) => Self::Http {
                exchange_id: exchange.id,
            },
            RecorderEvent::MysqlExchange(exchange) => {
                if crate::mysql::wire::is_no_response_command(&exchange.command)
                    || (exchange.outcome == crate::DependencyExchangeOutcome::Response
                        && ((exchange.command == "COM_PING" && exchange.response.status == "ok")
                            || (exchange.command == "COM_STMT_PREPARE"
                                && exchange.response.status == "stmt_prepare")))
                {
                    return None;
                }
                Self::Mysql {
                    connection_id: exchange.connection_id,
                    sequence: exchange.query_sequence,
                }
            }
            RecorderEvent::RedisExchange(exchange) => Self::Redis {
                connection_id: exchange.connection_id,
                sequence: exchange.sequence,
            },
            RecorderEvent::RedisPubSubPush(push) => {
                let publisher = push.rpc_request.as_ref()?;
                Self::RedisRpcPush {
                    connection_id: publisher.connection_id,
                    sequence: publisher.sequence,
                }
            }
            RecorderEvent::MemcachedExchange(exchange) => Self::Memcached {
                connection_id: exchange.connection_id,
                sequence: exchange.sequence,
            },
            RecorderEvent::MotanExchange(exchange) if !exchange.heartbeat => Self::Motan {
                connection_id: exchange.connection_id,
                sequence: exchange.sequence,
            },
            RecorderEvent::KafkaProduce(exchange) => Self::KafkaProduce {
                connection_id: exchange.connection_id,
                sequence: exchange.sequence,
            },
            RecorderEvent::KafkaFetch(exchange) => Self::KafkaFetch {
                connection_id: exchange.connection_id,
                sequence: exchange.sequence,
            },
            RecorderEvent::KafkaDelivery(exchange) => Self::KafkaDelivery {
                connection_id: exchange.connection_id,
                sequence: exchange.sequence,
            },
            _ => return None,
        })
    }
}

impl ActiveCaseRegistry {
    pub(crate) fn observe_stream_tail_event(
        &self,
        event: &RecorderEvent,
        targets: &DependencyTargets,
        recorded_in_case: bool,
    ) {
        self.observe_tail_reference(NativeReference::for_event(event).map(|reference| serde_json::from_value(serde_json::to_value(reference).expect("native reference serializes")).expect("native reference has an open envelope")), targets, recorded_in_case,
            matches!(event, RecorderEvent::UdpDatagram(_))
                || matches!(event, RecorderEvent::RedisPubSubPush(push) if push.rpc_request.is_none()),
            |stop| cleanup_candidate(event, stop));
    }
}

/// Source shutdown does not turn an unfinished dependency into a peer response.
/// This context is recorded separately; original outcome/error bytes stay intact.
fn cleanup_candidate(event: &RecorderEvent, stop: chrono::DateTime<chrono::Utc>) -> bool {
    let ended_after_stop = match event {
        RecorderEvent::DependencyConnectFailure(event) => event.timestamp >= stop,
        RecorderEvent::HttpExchange(event) => event.timestamp >= stop,
        RecorderEvent::RedisExchange(event) => event.timestamp >= stop,
        RecorderEvent::MysqlExchange(event) => event.timestamp >= stop,
        _ => false,
    };
    ended_after_stop
        && match event {
            RecorderEvent::DependencyConnectFailure(event) => {
                event.failure_kind == "engine_cancelled"
            }
            RecorderEvent::HttpExchange(event) => {
                event.outcome != crate::DependencyExchangeOutcome::Response
                    || (event.response_status.is_none() && event.error.is_some())
                    || event
                        .response_stream
                        .as_ref()
                        .is_some_and(|stream| !stream.complete)
            }
            RecorderEvent::MysqlExchange(event) => {
                event.outcome != crate::DependencyExchangeOutcome::Response
                    || event.response.status == "incomplete"
                    || event
                        .parse_warnings
                        .iter()
                        .any(|warning| warning == "engine cleanup interrupted MySQL capture")
            }
            RecorderEvent::RedisExchange(event) => {
                event.outcome != crate::DependencyExchangeOutcome::Response
                    || (event.response_kind == "other" && !event.replay_safe)
            }
            _ => false,
        }
}
