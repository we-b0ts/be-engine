//! Inspect business arguments after authenticated output loading, without storing plaintext.
use super::*;
use crate::interaction::socketio::{EngineIoPacket, SocketIoKind};

pub(super) fn summarize(event: &Value) -> (Value, Option<Value>) {
    let decoded = (|| {
        let message: crate::interaction::model::WireMessage =
            serde_json::from_value(event["message"].clone()).ok()?;
        if message.kind != crate::interaction::model::MessageKind::Text {
            return None;
        }
        crate::interaction::socketio::decode_engine_io_text(&message.data, 1024 * 1024).ok()
    })();
    let Some(decoded) = decoded else {
        return (unavailable(), None);
    };
    let EngineIoPacket::Message(packet) = decoded else {
        return (
            json!({"presence":"present","private":true,"protocol":"socket_io","kind":"transport_control","sequence":event.get("sequence")}),
            None,
        );
    };
    let business = matches!(
        packet.kind,
        SocketIoKind::Event
            | SocketIoKind::BinaryEvent
            | SocketIoKind::Ack
            | SocketIoKind::BinaryAck
    );
    let data = business.then(|| packet.arguments()).flatten();
    let summary = json!({"presence":"present","private":true,"protocol":"socket_io",
        "sequence":event.get("sequence"),"kind":packet.kind,"namespace":packet.namespace,
        "event":packet.event_name().map(|name|bounded(&json!(name))),"id":packet.id,
        "attachments":packet.attachments,"representation":"socketio_arguments",
        "data":data.as_ref().map(bounded)});
    (summary, data)
}
