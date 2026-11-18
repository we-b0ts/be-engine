use super::*;
use std::time::Duration;
use tokio::sync::Notify;
use traffic_protocol::connection::RecordedInput;
use uuid::Uuid;

const SUBSCRIBE: &[u8] = b"*2\r\n$9\r\nSUBSCRIBE\r\n$6\r\nevents\r\n";
const CONFIRMED: &[u8] = b"*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n";
const PUSH: &[u8] = b"*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$3\r\n\0\xff!\r\n";
const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";
const PONG: &[u8] = b"*2\r\n$4\r\npong\r\n$0\r\n\r\n";
const UNSUBSCRIBE: &[u8] = b"*2\r\n$11\r\nUNSUBSCRIBE\r\n$6\r\nevents\r\n";
const REMOVED: &[u8] = b"*3\r\n$11\r\nunsubscribe\r\n$6\r\nevents\r\n:0\r\n";

#[tokio::test]
async fn recording_assigns_an_interleaved_binary_push_to_its_confirmed_subscription() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, downstream) = tokio::io::duplex(4096);
        let (upstream, mut source) = tokio::io::duplex(4096);
        let sink = Arc::new(CaptureSink::default());
        let recorder = tokio::spawn(Native.capture_session(info()).unwrap().run(
            Box::new(downstream),
            Box::new(upstream),
            sink.clone(),
        ));
        client.write_all(SUBSCRIBE).await.unwrap();
        let mut command = [0; SUBSCRIBE.len()];
        source.read_exact(&mut command).await.unwrap();
        assert_eq!(command, SUBSCRIBE);
        source.write_all(CONFIRMED).await.unwrap();
        let mut confirmation = [0; CONFIRMED.len()];
        client.read_exact(&mut confirmation).await.unwrap();
        assert_eq!(confirmation, CONFIRMED);
        client.write_all(PING).await.unwrap();
        let mut command = [0; PING.len()];
        source.read_exact(&mut command).await.unwrap();
        assert_eq!(command, PING);
        source.write_all(PUSH).await.unwrap();
        source.write_all(PONG).await.unwrap();
        let mut frames = [0; PUSH.len() + PONG.len()];
        client.read_exact(&mut frames).await.unwrap();
        assert_eq!(&frames[..PUSH.len()], PUSH);
        assert_eq!(&frames[PUSH.len()..], PONG);
        client.shutdown().await.unwrap();
        recorder.await.unwrap().unwrap();

        let events = sink.0.lock().unwrap();
        let [subscribe, push, ping] = events.as_slice() else {
            panic!("expected one exchange, then one push, then another exchange");
        };
        let subscribe = Native
            .recorded_exchange(subscribe.payload())
            .unwrap()
            .unwrap();
        let notification = Native.recorded_exchange(push.payload()).unwrap().unwrap();
        let RecordedInput::Emission { after, .. } = notification.input else {
            panic!("push was not projected as a server emission");
        };
        assert_eq!(after, subscribe.reference);
        assert_eq!(notification.reference, push.facts().reference);
        let projection = notification.response.project().unwrap();
        assert_eq!(projection.values["/payload"].bytes, b"\0\xff!".as_slice());
        let translated = notification
            .response
            .encode(&std::collections::BTreeMap::from([(
                "/payload".to_owned(),
                Bytes::from_static(b"updated"),
            )]))
            .unwrap();
        assert_eq!(
            translated.as_ref(),
            crate::encode_array(&[b"message", b"events", b"updated"])
        );
        let mut inconsistent = push.payload().clone();
        inconsistent["capture"] = json!({"protocol_ref":notification.reference});
        inconsistent["subscription_sequence"] = 2.into();
        assert!(Native.recorded_exchange(&inconsistent).is_err());
        assert!(Native.recorded_exchange(ping.payload()).unwrap().is_some());
    })
    .await
    .unwrap();
}

#[derive(Default)]
struct SubscriberHost {
    ping_admitted: Arc<Notify>,
    push_written: Arc<Notify>,
}

impl RequestHost for SubscriberHost {
    fn execute(&self, _: Arc<dyn ProtocolMessage>) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async { anyhow::bail!("subscription request used pooled matching") })
    }

    fn execute_bound(
        &self,
        request: Arc<dyn ProtocolMessage>,
        after: Option<ProtocolRef>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            let command = request.project()?.structure["command"].clone();
            let (bytes, wait, notify) = match command.as_str().unwrap() {
                "SUBSCRIBE" => {
                    assert!(after.is_none());
                    (CONFIRMED, None, None)
                }
                "PING" => {
                    assert_eq!(after, Some(anchor()));
                    self.ping_admitted.notify_one();
                    (PONG, Some(self.push_written.clone()), None)
                }
                "UNSUBSCRIBE" => {
                    assert_eq!(after, Some(anchor()));
                    (REMOVED, None, None)
                }
                _ => panic!("unexpected bound command {command}"),
            };
            Ok(Box::new(Delivery {
                bytes,
                wait,
                notify,
            }) as Box<dyn ResponseDelivery>)
        })
    }

    fn next_message(
        &self,
        anchors: Vec<ProtocolRef>,
    ) -> NativeFuture<'_, Box<dyn ResponseDelivery>> {
        Box::pin(async move {
            assert_eq!(anchors, vec![anchor()]);
            self.ping_admitted.notified().await;
            Ok(Box::new(Delivery {
                bytes: PUSH,
                wait: None,
                notify: Some(self.push_written.clone()),
            }) as Box<dyn ResponseDelivery>)
        })
    }
}

fn anchor() -> ProtocolRef {
    ProtocolRef::connection("redis", Uuid::nil(), 1)
}

struct Delivery {
    bytes: &'static [u8],
    wait: Option<Arc<Notify>>,
    notify: Option<Arc<Notify>>,
}

impl ResponseDelivery for Delivery {
    fn ready(&mut self) -> NativeFuture<'_, ()> {
        Box::pin(async {
            if let Some(wait) = &self.wait {
                wait.notified().await;
                self.wait = None;
            }
            Ok(())
        })
    }

    fn reference(&self) -> Option<ProtocolRef> {
        (self.bytes == CONFIRMED).then(anchor)
    }

    fn write<'a>(
        self: Box<Self>,
        io: &'a mut dyn traffic_protocol::connection::OutputIo,
        framer: &'a mut dyn ResponseFramer,
    ) -> NativeFuture<'a, ()> {
        Box::pin(async move {
            io.write_all(&framer.frame(Bytes::from_static(self.bytes))?)
                .await?;
            io.flush().await?;
            if let Some(notify) = self.notify {
                notify.notify_one();
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn replay_can_deliver_a_push_between_command_admission_and_its_reply() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, io) = tokio::io::duplex(4096);
        let server = Native.server_session(info()).unwrap();
        let task = tokio::spawn(server.run(Box::new(io), Arc::new(SubscriberHost::default())));
        for (command, expected) in [
            (SUBSCRIBE, CONFIRMED.to_vec()),
            (PING, [PUSH, PONG].concat()),
            (UNSUBSCRIBE, REMOVED.to_vec()),
        ] {
            client.write_all(command).await.unwrap();
            let mut received = vec![0; expected.len()];
            client.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
        }
        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
