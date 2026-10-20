//! Parse incoming requests without confusing truncated frames with clean resets.
use super::*;

pub(super) async fn read(
    reader: tokio::net::tcp::OwnedReadHalf,
    incoming_sender: mpsc::Sender<IncomingEvent>,
) {
    let mut reader = crate::dependency::termination::ObservedIo::new(
        reader,
        crate::dependency::termination::ConnectionTermination::default(),
        crate::dependency::TerminationSide::Client,
    );
    let closed = loop {
        let before = reader.bytes_read();
        match read_frame(&mut reader, 64 * 1024 * 1024).await {
            Ok(Some(frame)) => {
                if incoming_sender
                    .send(IncomingEvent::Frame(frame))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Ok(None) => break Ok(()),
            Err(error) if reader.bytes_read() != before => {
                break Err(anyhow!(
                    "Motan target terminated inside an incomplete frame: {error:#}"
                ));
            }
            Err(error) => break Err(error),
        }
    };
    let _ = incoming_sender.send(IncomingEvent::Closed(closed)).await;
}
