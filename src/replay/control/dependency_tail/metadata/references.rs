//! Original semantic exchange identities shared by finite-tail inventories.
use super::*;
use serde_json::Value;

pub(in crate::replay::control::dependency_tail) fn reference(
    event: &Value,
) -> Result<Option<RecordedReference>> {
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
        Some("mysql_exchange") => {
            let command = event["command"]
                .as_str()
                .context("Source MySQL command missing")?;
            if crate::mysql::wire::is_no_response_command(command)
                || command == "COM_PING" && event["response"]["status"] == "ok"
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
        Some(
            "memcached_exchange" | "motan_exchange" | "kafka_produce" | "kafka_fetch"
            | "kafka_delivery",
        ) => anyhow::bail!(
            "Source inventory contains an unsupported finite-tail protocol; record with complete inventory support"
        ),
        _ => None,
    })
}
