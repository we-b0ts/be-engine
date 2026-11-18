use super::*;
use bytes::Bytes;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use traffic_model::recording::ProtocolRef;
use traffic_protocol::message::{MessageEncoder, ProjectedMessage, ProjectedValue};

const PROTOCOL: ProtocolId = ProtocolId::new("external-protocol");
struct Message(&'static str);
impl ProtocolMessage for Message {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: json!({"native":"message"}),
            values: BTreeMap::from([("value".into(), ProjectedValue::bytes(self.0))]),
        })
    }
    fn locate(&self, _: &Value) -> Result<Vec<String>> {
        Ok(vec!["value".into()])
    }
    fn evidence(&self, _: &Value) -> Result<Value> {
        Ok(json!({"native":"message"}))
    }
}
impl MessageEncoder for Message {
    fn encode(&self, values: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        Ok(values["value"].clone())
    }
}

fn endpoint() -> Endpoint {
    Endpoint {
        host: "native.test".into(),
        port: 8029,
    }
}

fn inventory(source: ReplaySource) -> ExchangeInventory {
    let mut inventory = ExchangeInventory::default();
    for (position, value) in ["first", "second"].into_iter().enumerate() {
        inventory
            .register(
                PROTOCOL,
                RecordedExchange {
                    reference: ProtocolRef::exchange(PROTOCOL.as_str(), Uuid::new_v4()),
                    endpoint: endpoint(),
                    lane: Some("native-session".into()),
                    response_delay: std::time::Duration::ZERO,
                    request: Arc::new(Message(value)),
                    response: Arc::new(Message(value)),
                },
                SourceContext {
                    source,
                    case_id: (source == ReplaySource::Case).then(|| "case".into()),
                    position: position as u64,
                    capture: None,
                },
                ExchangeRules::default(),
            )
            .unwrap();
    }
    inventory.seal();
    inventory
}

fn select(inventory: &ExchangeInventory, source: ReplaySource, value: &'static str) -> Selection {
    inventory
        .select(
            MatchContext {
                protocol: PROTOCOL,
                endpoint: &endpoint(),
                active_case: (source == ReplaySource::Case).then_some("case"),
                request: &Message(value),
                metadata: &(),
            },
            |_| (),
            |_, _| Ok(()),
        )
        .unwrap()
}

#[test]
fn case_pipeline_admission_preserves_the_separate_real_delivery_barrier() {
    let mut inventory = inventory(ReplaySource::Case);
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "second"),
        Selection::LaneBlocked { blocker: 0, .. }
    ));
    let first = inventory.claim(0).unwrap();
    assert!(matches!(
        select(&inventory, ReplaySource::Case, "second"),
        Selection::Matched(selected) if selected.index == 1
    ));
    let second = inventory.claim(1).unwrap();
    assert!(matches!(
        inventory.finish(1, &second, || Ok(())),
        Finish::Unchanged
    ));
    assert!(!inventory.exchanges[1].status.is_consumed());
    assert!(first.publish_wire());
    assert!(matches!(
        inventory.finish(0, &first, || Ok(())),
        Finish::Committed(())
    ));
    drop(second);
    assert_eq!(
        inventory
            .lifecycle
            .live_status(1, inventory.exchanges[1].status),
        ReplayExchangeStatus::Failed
    );
}

#[test]
fn run_owned_lanes_keep_the_predecessors_actual_delivery_requirement() {
    let mut inventory = inventory(ReplaySource::Startup);
    let first = inventory.claim(0).unwrap();
    assert!(matches!(
        select(&inventory, ReplaySource::Startup, "second"),
        Selection::LaneBlocked { blocker: 0, .. }
    ));
    assert!(first.publish_wire());
    assert!(matches!(
        inventory.finish(0, &first, || Ok(())),
        Finish::Committed(())
    ));
    assert!(matches!(
        select(&inventory, ReplaySource::Startup, "second"),
        Selection::Matched(selected) if selected.index == 1
    ));
}

#[test]
fn native_reference_resolution_retains_case_ownership_and_rejects_ambiguity() {
    let mut inventory = inventory(ReplaySource::Case);
    let reference = inventory.exchanges[0].native.reference.clone();
    assert_eq!(
        inventory.resolve_reference("case", &reference).unwrap(),
        Some(0)
    );
    assert_eq!(
        inventory
            .resolve_reference("other-case", &reference)
            .unwrap(),
        None
    );
    assert_eq!(
        inventory.exchanges[0].status,
        ReplayExchangeStatus::Available
    );
    inventory
        .register(
            PROTOCOL,
            RecordedExchange {
                reference: reference.clone(),
                endpoint: endpoint(),
                lane: None,
                response_delay: std::time::Duration::ZERO,
                request: Arc::new(Message("duplicate")),
                response: Arc::new(Message("duplicate")),
            },
            SourceContext {
                source: ReplaySource::Case,
                case_id: Some("case".into()),
                position: 3,
                capture: None,
            },
            ExchangeRules::default(),
        )
        .unwrap();
    assert!(inventory.resolve_reference("case", &reference).is_err());
    assert_eq!(
        inventory.exchanges[0].status,
        ReplayExchangeStatus::Available
    );
}

#[test]
fn comparison_observers_receive_failed_candidates_without_consuming_their_inventory() {
    let inventory = inventory(ReplaySource::Case);
    let observations = RefCell::new(Vec::new());
    let selected = inventory
        .select_observed(
            MatchContext {
                protocol: PROTOCOL,
                endpoint: &endpoint(),
                active_case: Some("case"),
                request: &Message("different"),
                metadata: &(),
            },
            |_| (),
            |_, _| Ok(()),
            |exchange, comparison| {
                observations
                    .borrow_mut()
                    .push((exchange.index, *comparison));
                Ok(())
            },
        )
        .unwrap();
    assert!(matches!(selected, Selection::NotFound));
    assert_eq!(*observations.borrow(), vec![(0, false), (1, false)]);
    assert!(
        inventory
            .exchanges
            .iter()
            .all(|exchange| exchange.status == ReplayExchangeStatus::Available)
    );
    let failed = inventory.select_observed(
        MatchContext {
            protocol: PROTOCOL,
            endpoint: &endpoint(),
            active_case: Some("case"),
            request: &Message("first"),
            metadata: &(),
        },
        |_| (),
        |_, _| Ok(()),
        |_, _| anyhow::bail!("observer unavailable"),
    );
    assert!(failed.is_err());
    assert!(
        inventory
            .exchanges
            .iter()
            .all(|exchange| exchange.status == ReplayExchangeStatus::Available)
    );
}
