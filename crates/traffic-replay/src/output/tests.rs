use super::*;
use crate::{SequencePlan, SequenceRuntime, SourceEvent};
use bytes::Bytes;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::io::AsyncReadExt;
use traffic_protocol::output::{OutputChunk, SingleOutput};

struct Output {
    parts: usize,
    chunks: VecDeque<OutputChunk>,
}

impl OutputStream for Output {
    fn part_count(&self) -> usize {
        self.parts
    }
    fn next(&mut self) -> Result<Option<OutputChunk>> {
        Ok(self.chunks.pop_front())
    }
}

fn chunk(bytes: &'static str, boundary: OutputBoundary, complete: bool) -> OutputChunk {
    OutputChunk {
        bytes: Bytes::from_static(bytes.as_bytes()),
        boundary,
        complete,
    }
}

fn output() -> Output {
    Output {
        parts: 2,
        chunks: VecDeque::from([
            chunk("h1", OutputBoundary::Headers, false),
            chunk("h2", OutputBoundary::Headers, true),
            chunk("a0", OutputBoundary::Part, false),
            chunk("a1", OutputBoundary::Part, true),
            chunk("b", OutputBoundary::Part, true),
            chunk("e", OutputBoundary::End, true),
        ]),
    }
}

fn runtime(events: &[(u64, EventKind)]) -> Arc<SequenceRuntime> {
    SequenceRuntime::new(
        SequencePlan::compile(events.iter().enumerate().map(
            |(index, &(dependency_sequence, kind))| SourceEvent {
                sequence: index as u64 + 1,
                dependency_sequence,
                offset_micros: index as u64,
                kind,
            },
        ))
        .unwrap(),
    )
}

fn ordinary_runtime() -> Arc<SequenceRuntime> {
    runtime(&[
        (1, EventKind::Request),
        (1, EventKind::ResponseHeaders),
        (1, EventKind::ResponsePart),
        (1, EventKind::ResponsePart),
        (1, EventKind::ResponseEnd),
    ])
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    flushes: Vec<Vec<u8>>,
    fail_flush: Option<usize>,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let bytes = self.bytes.clone();
        self.flushes.push(bytes);
        Poll::Ready(if self.fail_flush == Some(self.flushes.len()) {
            Err(std::io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[tokio::test]
async fn native_events_share_ordered_batching_and_retain_the_callers_terminal_receipt() {
    let runtime = ordinary_runtime();
    let claim = runtime.admit(1).unwrap();
    claim
        .wait_delivery(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let mut writer = Writer::default();
    deliver(&mut writer, &mut output(), Some(&claim))
        .await
        .unwrap();
    assert_eq!(
        writer.flushes,
        [
            b"h1h2".to_vec(),
            b"h1h2a0a1b".to_vec(),
            b"h1h2a0a1be".to_vec()
        ]
    );
    assert_eq!(claim.reserved_kind(), Some(EventKind::ResponseEnd));
    assert!(!runtime.complete());
    claim.publish().unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn another_dependency_barrier_prevents_the_next_native_part_from_becoming_visible() {
    let runtime = runtime(&[
        (1, EventKind::Request),
        (1, EventKind::ResponseHeaders),
        (1, EventKind::ResponsePart),
        (2, EventKind::Request),
        (2, EventKind::ResponseEnd),
        (1, EventKind::ResponsePart),
        (1, EventKind::ResponseEnd),
    ]);
    let claim = runtime.admit(1).unwrap();
    claim
        .wait_delivery(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(64);
    let delivery = tokio::spawn(async move {
        let result = deliver(&mut writer, &mut output(), Some(&claim)).await;
        (result, claim)
    });
    let mut prefix = [0; 8];
    reader.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"h1h2a0a1");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), reader.read_u8())
            .await
            .is_err()
    );
    let other = runtime.admit(2).unwrap();
    other
        .wait_delivery(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    let mut second_wire = Vec::new();
    deliver(
        &mut second_wire,
        &mut SingleOutput::new(Bytes::from_static(b"other")),
        Some(&other),
    )
    .await
    .unwrap();
    assert_eq!(second_wire, b"other");
    other.publish().unwrap();
    let mut tail = Vec::new();
    reader.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, b"be");
    let (result, claim) = delivery.await.unwrap();
    result.unwrap();
    assert!(!runtime.complete());
    claim.publish().unwrap();
    assert!(runtime.complete());
}

#[tokio::test]
async fn failed_flush_preserves_every_unconfirmed_native_boundary() {
    for (failed_flush, expected) in [
        (1, EventKind::ResponseHeaders),
        (2, EventKind::ResponsePart),
        (3, EventKind::ResponseEnd),
    ] {
        let runtime = ordinary_runtime();
        let claim = runtime.admit(1).unwrap();
        claim
            .wait_delivery(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let mut writer = Writer {
            fail_flush: Some(failed_flush),
            ..Default::default()
        };
        assert!(
            deliver(&mut writer, &mut output(), Some(&claim))
                .await
                .is_err()
        );
        assert_eq!(claim.reserved_kind(), Some(expected));
        assert!(!runtime.complete());
        claim.fail();
    }
}

#[tokio::test]
async fn incomplete_reordered_or_extra_native_outputs_cannot_finish_a_response() {
    for chunks in [
        vec![
            chunk("h", OutputBoundary::Headers, false),
            chunk("e", OutputBoundary::End, true),
        ],
        vec![
            chunk("a", OutputBoundary::Part, true),
            chunk("h", OutputBoundary::Headers, true),
        ],
        vec![
            chunk("e", OutputBoundary::End, true),
            chunk("extra", OutputBoundary::End, true),
        ],
        vec![chunk("h", OutputBoundary::Headers, true)],
    ] {
        let mut output = Output {
            parts: 0,
            chunks: chunks.into(),
        };
        assert!(deliver(&mut Vec::new(), &mut output, None).await.is_err());
    }
}
