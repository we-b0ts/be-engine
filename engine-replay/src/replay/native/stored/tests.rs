use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use traffic_model::recording::ProtocolRef;
use traffic_protocol::connection::{RecordedExchange, RecordedInput};
use traffic_replay::exchange::{ExchangeRules, SourceContext};

struct TestResponse {
    stored: bool,
    decoded_drops: Arc<AtomicUsize>,
}

impl Drop for TestResponse {
    fn drop(&mut self) {
        if !self.stored {
            self.decoded_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl ProtocolMessage for TestResponse {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: Value::Null,
            values: BTreeMap::new(),
        })
    }

    fn locate(&self, _: &Value) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn evidence(&self, _: &Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

impl MessageEncoder for TestResponse {
    fn stored(&self) -> Option<&dyn StoredMessage> {
        self.stored.then_some(self)
    }

    fn prefetch_retained_bytes(&self) -> Option<usize> {
        Some(std::mem::size_of::<Self>() + 5)
    }

    fn prefetch_packet(&self, values: &BTreeMap<String, Bytes>) -> Result<Option<(Bytes, usize)>> {
        Ok(Some((self.encode(values)?, 0)))
    }

    fn encode(&self, _: &BTreeMap<String, Bytes>) -> Result<Bytes> {
        Ok(Bytes::from_static(b"frame"))
    }
}

impl StoredMessage for TestResponse {
    fn load(&self) -> Result<Arc<dyn MessageEncoder>> {
        Ok(Arc::new(Self {
            stored: false,
            decoded_drops: self.decoded_drops.clone(),
        }))
    }
}

#[test]
fn compact_response_releases_decoder_before_replay_and_falls_back_for_another_owner() {
    let mut inventory = Inventory::new(Arc::default());
    inventory.prepare_event_session();
    inventory.configure_session_identities(2).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let protocol = ProtocolId::new("redis");
    let index = inventory
        .core
        .register(
            protocol,
            RecordedExchange {
                reference: ProtocolRef::connection("redis", Uuid::nil(), 2),
                endpoint: Endpoint {
                    host: "example.invalid".into(),
                    port: 6379,
                },
                lane: None,
                response_delay: Default::default(),
                input: RecordedInput::Emission {
                    after: ProtocolRef::connection("redis", Uuid::nil(), 1),
                    offset: Default::default(),
                },
                response: Arc::new(TestResponse {
                    stored: true,
                    decoded_drops: drops.clone(),
                }),
            },
            SourceContext {
                source: ReplaySource::Startup,
                case_id: None,
                position: 2,
                capture: None,
            },
            ExchangeRules::default(),
        )
        .unwrap();
    let prepare = inventory.stored_response_preparation(index).unwrap();
    let mut stable = prepare.load(4096).unwrap().unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(stable.has_source_preparation());
    assert!(stable.has_compact_packet());
    assert_eq!(
        inventory.batchable_message_packet(index, &stable).unwrap(),
        b"frame".as_slice()
    );

    let (mut output, used) = inventory
        .render_prefetched_response(index, Utc::now(), &mut stable, &Default::default())
        .unwrap();
    assert!(used);
    assert_eq!(
        output.output.next().unwrap().unwrap().bytes,
        b"frame".as_slice()
    );
    assert_eq!(drops.load(Ordering::Relaxed), 1);

    let mut old_owner = prepare.load(4096).unwrap().unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    inventory.contracts = crate::value_extensions::strict_values();
    inventory.configure_session_identities(2).unwrap();
    assert!(
        inventory
            .batchable_message_packet(index, &old_owner)
            .is_none()
    );
    let (mut output, used) = inventory
        .render_prefetched_response(index, Utc::now(), &mut old_owner, &Default::default())
        .unwrap();
    assert!(!used);
    assert_eq!(
        output.output.next().unwrap().unwrap().bytes,
        b"frame".as_slice()
    );
    assert_eq!(drops.load(Ordering::Relaxed), 3);
}
