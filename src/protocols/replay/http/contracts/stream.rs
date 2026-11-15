//! Preserve stream timing while deriving new JSON data byte ranges.
use crate::{http::stream::ResponseStream, value_codec::sse::Document};
use anyhow::{Result, ensure};

pub(super) fn remap(stream: &mut ResponseStream, source: &[u8], target: &[u8]) -> Result<()> {
    remap_inner(stream, source, target, true)
}

pub(super) fn remap_prefix(
    stream: &mut ResponseStream,
    source: &[u8],
    target: &[u8],
) -> Result<()> {
    remap_inner(stream, source, target, false)
}

fn remap_inner(
    stream: &mut ResponseStream,
    source: &[u8],
    target: &[u8],
    complete: bool,
) -> Result<()> {
    if complete {
        stream.validate(source.len())?;
    } else {
        stream.validate_prefix(source.len())?;
    }
    let framed = Document::decode(source)
        .ok()
        .map(|source| Document::decode(target).map(|target| (source, target)))
        .transpose()?;
    let map = |offset| -> Result<usize> {
        if let Some((source, target)) = &framed {
            source.map_offset(target, offset)
        } else {
            ensure!(
                !source.is_empty() && crate::json_value::parse(source).is_some(),
                "changed stream has no known Source format"
            );
            Ok(offset * target.len() / source.len())
        }
    };
    let mut chunks = Vec::new();
    for mut chunk in std::mem::take(&mut stream.chunks) {
        chunk.start = map(chunk.start)?;
        chunk.end = map(chunk.end)?;
        if chunk.end > chunk.start {
            chunks.push(chunk);
        }
    }
    stream.chunks = chunks;
    if complete {
        stream.validate(target.len())
    } else {
        stream.validate_prefix(target.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::stream::ResponseChunk;
    #[test]
    fn derived_sse_event_completes_at_original_chunk_time_after_length_changes() {
        let source =
            b": heartbeat\nevent: delta\ndata: { \"created_at\": 1005 }\n\ndata: [DONE]\n\n";
        let document = Document::decode(source).unwrap();
        let target = document
            .render(&[br#"{"created_at":2005}"#.to_vec(), b"[DONE]".to_vec()])
            .unwrap();
        let end_of_first = source
            .windows(2)
            .position(|value| value == b"\n\n")
            .unwrap()
            + 2;
        let mut stream = ResponseStream {
            version: 1,
            headers_ms: 10,
            chunks: vec![
                ResponseChunk {
                    at_ms: 20,
                    start: 0,
                    end: 35,
                },
                ResponseChunk {
                    at_ms: 30,
                    start: 35,
                    end: end_of_first,
                },
                ResponseChunk {
                    at_ms: 40,
                    start: end_of_first,
                    end: source.len(),
                },
            ],
            end_ms: 50,
            complete: true,
            trailers: None,
        };
        remap(&mut stream, source, &target).unwrap();
        assert_eq!(stream.headers_ms, 10);
        assert_eq!(stream.end_ms, 50);
        assert_eq!(
            stream
                .chunks
                .iter()
                .map(|chunk| chunk.at_ms)
                .collect::<Vec<_>>(),
            vec![20, 30, 40]
        );
        let first_end = stream.chunks[1].end;
        assert!(Document::decode(&target[..first_end]).is_ok());
        assert!(Document::decode(&target[..first_end - 1]).is_err());
        stream.validate(target.len()).unwrap();
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    #[test]
    fn rebase_incomplete_json_prefix_preserves_timing_and_does_not_invent_eof() {
        let source = br#"{ "id": "source" }"#;
        let target = br#"{"id":"target-longer"}"#;
        let mut stream = ResponseStream {
            version: 2,
            headers_ms: 2,
            chunks: vec![crate::http::stream::ResponseChunk {
                at_ms: 4,
                start: 0,
                end: source.len(),
            }],
            end_ms: 15,
            complete: false,
            trailers: None,
        };
        remap_prefix(&mut stream, source, target).unwrap();
        assert!(!stream.complete);
        assert_eq!(stream.chunks[0].end, target.len());
        assert_eq!(stream.chunks[0].at_ms, 4);
        assert_eq!(stream.end_ms, 15);
        assert!(stream.validate(target.len()).is_err());
        stream.validate_prefix(target.len()).unwrap();
    }
}
