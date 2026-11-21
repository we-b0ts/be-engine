//! Preserve transparent forwarding after semantic framing has failed closed.
use super::{ConnectionTermination, ObservedIo, TerminationSide};
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Flush decoder-consumed bytes, then forward undecodable traffic until its
/// actual peer termination. The protocol owner keeps the capture unsafe and
/// mirrors any observed FIN/RST separately; a parser error proves neither.
pub async fn forward_captured<R, W>(
    reader: &mut ObservedIo<R>,
    writer: &mut W,
    termination: &ConnectionTermination,
    side: TerminationSide,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + ?Sized,
{
    if termination.engine_stopped() {
        return Ok(());
    }
    writer.write_all(reader.captured()).await?;
    writer.flush().await?;
    reader.stop_capture();
    if termination.observed(side).is_none() && !termination.engine_stopped() {
        let copied = tokio::io::copy(reader, writer).await;
        let flushed = writer.flush().await;
        copied?;
        flushed?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use traffic_model::TerminationKind;

    #[tokio::test]
    async fn decoder_failure_forwards_prefix_and_tail_without_inventing_a_close() {
        let (mut upstream, incoming) = tokio::io::duplex(32);
        let (mut outgoing, mut client) = tokio::io::duplex(32);
        upstream.write_all(b"bad-header").await.unwrap();
        let termination = ConnectionTermination::default();
        let mut reader = ObservedIo::new(incoming, termination.clone(), TerminationSide::Server);
        reader.begin_capture(32);
        reader.read_exact(&mut [0; 10]).await.unwrap();
        // The decoder rejects the header before its peer has ended anything.
        assert!(termination.peer_snapshot().is_none());
        let forward = tokio::spawn(async move {
            forward_captured(
                &mut reader,
                &mut outgoing,
                &termination,
                TerminationSide::Server,
            )
            .await
            .unwrap();
            assert_eq!(
                termination
                    .observed(TerminationSide::Server)
                    .unwrap()
                    .termination
                    .kind,
                TerminationKind::Eof
            );
            outgoing
        });
        let mut header = [0; 10];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(&header, b"bad-header");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.read_u8())
                .await
                .is_err()
        );
        upstream.write_all(b"-tail").await.unwrap();
        upstream.shutdown().await.unwrap();
        let _outgoing = forward.await.unwrap();
        let mut tail = [0; 5];
        client.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"-tail");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.read_u8())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn capture_bound_never_consumes_and_loses_the_raw_fallback_tail() {
        let (mut upstream, incoming) = tokio::io::duplex(16);
        let (mut outgoing, mut client) = tokio::io::duplex(16);
        upstream.write_all(b"abcdef").await.unwrap();
        upstream.shutdown().await.unwrap();
        let termination = ConnectionTermination::default();
        let mut reader = ObservedIo::new(incoming, termination.clone(), TerminationSide::Server);
        reader.begin_capture(2);
        let error = reader.read_exact(&mut [0; 4]).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(reader.capture_truncated());
        assert!(termination.peer_snapshot().is_none());
        forward_captured(
            &mut reader,
            &mut outgoing,
            &termination,
            TerminationSide::Server,
        )
        .await
        .unwrap();
        let mut delivered = [0; 6];
        client.read_exact(&mut delivered).await.unwrap();
        assert_eq!(&delivered, b"abcdef");
        assert_eq!(
            termination
                .observed(TerminationSide::Server)
                .unwrap()
                .termination
                .kind,
            TerminationKind::Eof
        );
    }
}
