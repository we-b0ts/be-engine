//! Original semantic exchange identities shared by finite-tail inventories.
use super::*;
use serde_json::Value;

pub(in crate::replay::control::dependency_tail) fn reference(
    event: &Value,
) -> Result<Option<RecordedReference>> {
    // The central ledger retains protocol observations without creating finite
    // business obligations. Missing legacy metadata keeps the ordinary guards.
    if event["capture"]["semantic_required"] == false {
        return Ok(None);
    }
    let uuid = |field| {
        event[field]
            .as_str()
            .context("Source exchange identity missing")?
            .parse()
            .context("invalid Source exchange identity")
    };
    let sequence = |field| {
        event[field]
            .as_u64()
            .context("Source exchange sequence missing")
    };
    Ok(match event["event_type"].as_str() {
        Some("dependency_connect_failure") => Some(RecordedReference::Connect {
            event_id: uuid("id")?,
        }),
        Some("http_exchange") => Some(RecordedReference::Http {
            exchange_id: uuid("id")?,
        }),
        Some("redis_exchange") => Some(RecordedReference::Redis {
            connection_id: uuid("connection_id")?,
            sequence: sequence("sequence")?,
        }),
        Some("redis_pub_sub_push") if event["rpc_request"].is_object() => {
            Some(RecordedReference::RedisRpcPush {
                connection_id: event["rpc_request"]["connection_id"]
                    .as_str()
                    .context("Redis callback publisher identity missing")?
                    .parse()?,
                sequence: event["rpc_request"]["sequence"]
                    .as_u64()
                    .context("Redis callback publisher sequence missing")?,
            })
        }
        Some("mysql_exchange") => {
            let command = event["command"]
                .as_str()
                .context("Source MySQL command missing")?;
            if crate::mysql::wire::is_no_response_command(command)
                || command == "COM_PING"
                || command == "COM_STMT_PREPARE" && event["response"]["status"] == "stmt_prepare"
            {
                None
            } else {
                Some(RecordedReference::Mysql {
                    connection_id: uuid("connection_id")?,
                    sequence: sequence("query_sequence")?,
                })
            }
        }
        Some("memcached_exchange") => Some(RecordedReference::Memcached {
            connection_id: uuid("connection_id")?,
            sequence: sequence("sequence")?,
        }),
        Some("motan_exchange") if event["heartbeat"] != true => Some(RecordedReference::Motan {
            connection_id: uuid("connection_id")?,
            sequence: sequence("sequence")?,
        }),
        Some("kafka_produce") => Some(RecordedReference::KafkaProduce {
            connection_id: uuid("connection_id")?,
            sequence: sequence("sequence")?,
        }),
        Some("kafka_fetch") => Some(RecordedReference::KafkaFetch {
            connection_id: uuid("connection_id")?,
            sequence: sequence("sequence")?,
        }),
        Some("kafka_delivery") => Some(RecordedReference::KafkaDelivery {
            connection_id: uuid("connection_id")?,
            sequence: sequence("sequence")?,
        }),
        Some("udp_datagram") => anyhow::bail!("finite-tail UDP replay is unsupported"),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn mysql_ping_failure_is_not_a_dispatch_obligation() {
        let event = json!({
            "event_type":"mysql_exchange", "connection_id":Uuid::new_v4(),
            "query_sequence":7, "command":"COM_PING", "capture":{"semantic_required":true},
            "response":{"status":"error","error_code":2006}
        });
        assert!(reference(&event).unwrap().is_none());
    }

    #[test]
    fn central_redis_control_observations_are_not_finite_tail_obligations() {
        let connection = Uuid::new_v4();
        let mut event = json!({
            "event_type":"redis_exchange", "connection_id":connection,
            "sequence":7, "command":"AUTH",
            "capture":{"semantic_required":false}
        });
        assert!(reference(&event).unwrap().is_none());
        event["capture"]["semantic_required"] = true.into();
        assert_eq!(
            reference(&event).unwrap(),
            Some(RecordedReference::Redis {
                connection_id: connection,
                sequence: 7
            })
        );
        event.as_object_mut().unwrap().remove("capture");
        assert!(reference(&event).unwrap().is_some());
    }

    #[test]
    fn native_finite_inventory_preserves_kafka_effects_and_excludes_only_heartbeats() {
        let connection = Uuid::new_v4();
        for (event, field, expected) in [
            ("memcached_exchange", "sequence", "memcached"),
            ("motan_exchange", "sequence", "motan"),
            ("kafka_produce", "sequence", "kafka_produce"),
            ("kafka_fetch", "sequence", "kafka_fetch"),
            ("kafka_delivery", "sequence", "kafka_delivery"),
        ] {
            let mut raw = json!({"event_type":event,"connection_id":connection,"heartbeat":false,"request_sequence":1,"fetch_sequence":1});
            raw[field] = json!(7);
            let selected = reference(&raw).unwrap().unwrap();
            assert_eq!(
                serde_json::to_value(selected).unwrap(),
                json!({"protocol":expected,"connection_id":connection,"sequence":7})
            );
            raw.as_object_mut().unwrap().remove(field);
            assert!(
                reference(&raw).is_err(),
                "missing native semantic identity must stay incomplete"
            );
        }
        assert!(
            reference(&json!({"event_type":"motan_exchange","heartbeat":true}))
                .unwrap()
                .is_none()
        );
        assert!(reference(&json!({"event_type":"udp_datagram"})).is_err());
    }
}
