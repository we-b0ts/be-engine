use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::AsyncWrite;

use super::*;

#[derive(Default)]
struct ShortWriter {
    limits: VecDeque<Result<usize, ErrorKind>>,
    output: Vec<u8>,
    flushes: usize,
}

impl AsyncWrite for ShortWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        panic!("expected a vectored write")
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let limit = match self.limits.pop_front().expect("scripted write") {
            Ok(limit) => limit,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        let mut remaining = limit;
        for slice in slices {
            let count = slice.len().min(remaining);
            self.output.extend_from_slice(&slice[..count]);
            remaining -= count;
        }
        Poll::Ready(Ok(limit - remaining))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn frames() -> [Bytes; 3] {
    [b"one", b"two", b"six"].map(|frame| Bytes::from_static(frame))
}

#[tokio::test]
async fn short_writes_resume_at_the_next_byte_and_flush_once() {
    let mut writer = ShortWriter {
        limits: [Ok(4), Ok(2), Ok(9)].into(),
        ..Default::default()
    };
    let result = write_message_batch(&mut writer, &frames()).await;
    assert!(result.error.is_none());
    assert_eq!(result.completed_frames, 3);
    assert_eq!(result.writes, 3);
    assert_eq!(writer.output, b"onetwosix");
    assert_eq!(writer.flushes, 1);
}

#[tokio::test]
async fn failed_write_reports_only_complete_frames_in_accepted_prefix() {
    let mut writer = ShortWriter {
        limits: [Ok(7), Err(ErrorKind::BrokenPipe)].into(),
        ..Default::default()
    };
    let result = write_message_batch(&mut writer, &frames()).await;
    assert_eq!(result.error.unwrap().kind(), ErrorKind::BrokenPipe);
    assert_eq!(result.completed_frames, 2);
    assert_eq!(result.writes, 2);
    assert_eq!(writer.output, b"onetwos");
    assert_eq!(writer.flushes, 0);
}
