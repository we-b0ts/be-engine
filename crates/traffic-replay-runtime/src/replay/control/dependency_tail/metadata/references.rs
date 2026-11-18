//! Original semantic exchange identities supplied by native evidence capabilities.
use super::*;
use serde_json::Value;
use traffic_protocol::evidence::EvidenceRegistry;

pub(crate) fn reference(
    event: &Value,
    evidence: &EvidenceRegistry,
) -> Result<Option<RecordedReference>> {
    if event["capture"]["semantic_required"] == false {
        return Ok(None);
    }
    if event["event_type"] == "dependency_connect_failure" {
        let event_id: uuid::Uuid = event["id"]
            .as_str()
            .context("Source connection failure identity missing")?
            .parse()?;
        return Ok(Some(RecordedReference::new(
            "connect",
            serde_json::json!({"event_id": event_id}),
        )?));
    }
    evidence.finite_reference(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn reference(event: &Value) -> Result<Option<RecordedReference>> {
        super::reference(event, crate::protocols::default_providers().evidence())
    }

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
            Some(RecordedReference::connection("redis", connection, 7))
        );
        event.as_object_mut().unwrap().remove("capture");
        assert!(reference(&event).unwrap().is_some());
    }

    #[test]
    fn native_finite_inventory_preserves_original_identities() {
        let connection = Uuid::new_v4();
        for (event, field, expected) in [
            ("redis_exchange", "sequence", "redis"),
            ("mysql_exchange", "query_sequence", "mysql"),
        ] {
            let mut raw = json!({"event_type":event,"connection_id":connection,"command":"COM_QUERY","request_sequence":1});
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
