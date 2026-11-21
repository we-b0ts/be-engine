use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll};
use traffic_protocol::connection::CaptureOutput;

struct Receipt {
    committed: Arc<AtomicUsize>,
    abandoned: Arc<AtomicUsize>,
    delivered: bool,
}

impl CaptureOutput for Receipt {
    fn commit(mut self: Box<Self>) {
        self.delivered = true;
        self.committed.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for Receipt {
    fn drop(&mut self) {
        if !self.delivered {
            self.abandoned.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct Writer {
    fail_flush: bool,
    bytes: Vec<u8>,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(if self.fail_flush {
            Err(std::io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        })
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[tokio::test]
async fn rejected_capture_completes_only_after_the_native_error_is_flushed() {
    for fail_flush in [false, true] {
        let committed = Arc::new(AtomicUsize::new(0));
        let abandoned = Arc::new(AtomicUsize::new(0));
        let mut writer = Writer {
            fail_flush,
            bytes: Vec::new(),
        };
        let result = write_rejection(
            &mut writer,
            u8::MAX,
            Box::new(Receipt {
                committed: committed.clone(),
                abandoned: abandoned.clone(),
                delivered: false,
            }),
        )
        .await;
        assert_eq!(writer.bytes, readonly_error_packet(0).to_wire_bytes());
        assert_eq!(result.is_ok(), !fail_flush);
        assert_eq!(committed.load(Ordering::SeqCst), usize::from(!fail_flush));
        assert_eq!(abandoned.load(Ordering::SeqCst), usize::from(fail_flush));
    }
}
