//! Native response messages and finite logical boundaries for shared delivery.
use anyhow::Result;
use bytes::Bytes;
use traffic_protocol::output::{OutputBoundary, OutputChunk, OutputStream};

use crate::{
    MysqlPacket, continuation, diagnostics,
    model::ResultRowEncoding,
    prepare::{StatementMetadata, prepare_messages},
    recorded::RecordedMysqlResponse,
    response::*,
    values::lenenc_int,
};

struct Message {
    payload: Vec<u8>,
    boundary: OutputBoundary,
    complete: bool,
}

struct Envelope {
    sequence: u8,
    next_sequence: u8,
    payload_bytes: usize,
    leading_byte: Option<u8>,
}

pub struct ResponseOutput<'a> {
    messages: Box<dyn Iterator<Item = Result<Message>> + Send + 'a>,
    cached: Option<Bytes>,
    next_sequence: u8,
    parts: usize,
    last: Option<Envelope>,
    write_context: &'static str,
    end_context: &'static str,
}

impl<'a> ResponseOutput<'a> {
    fn new(
        messages: impl Iterator<Item = Result<Message>> + Send + 'a,
        parts: usize,
        end_context: &'static str,
    ) -> Self {
        Self {
            messages: Box::new(messages),
            cached: None,
            next_sequence: 1,
            parts,
            last: None,
            write_context: "failed to write MySQL replay message",
            end_context,
        }
    }
}

impl OutputStream for ResponseOutput<'_> {
    fn part_count(&self) -> usize {
        self.parts
    }

    fn next(&mut self) -> Result<Option<OutputChunk>> {
        if let Some(bytes) = self.cached.take() {
            self.last = None;
            return Ok(Some(OutputChunk {
                bytes,
                boundary: OutputBoundary::End,
                complete: true,
            }));
        }
        let Some(message) = self.messages.next().transpose()? else {
            return Ok(None);
        };
        let packet = MysqlPacket {
            sequence_id: self.next_sequence,
            payload: message.payload,
        };
        let (bytes, next_sequence) = continuation::encode_message(&packet)?;
        self.next_sequence = next_sequence;
        self.last = Some(Envelope {
            sequence: packet.sequence_id,
            next_sequence,
            payload_bytes: packet.payload.len(),
            leading_byte: packet.payload.first().copied(),
        });
        Ok(Some(OutputChunk {
            bytes,
            boundary: message.boundary,
            complete: message.complete,
        }))
    }

    fn written(&mut self, success: bool) {
        if let Some(envelope) = &self.last {
            diagnostics::response_envelope(
                envelope.sequence,
                envelope.payload_bytes,
                envelope.leading_byte,
                success.then_some(envelope.next_sequence),
            );
        }
    }

    fn flushed(&mut self, success: bool) {
        diagnostics::flushed(success);
    }

    fn write_context(&self) -> &'static str {
        self.write_context
    }

    fn flush_context(&self, boundary: OutputBoundary) -> &'static str {
        match boundary {
            OutputBoundary::Headers => "failed to flush MySQL result metadata",
            OutputBoundary::Part => "failed to flush MySQL result rows",
            OutputBoundary::End
            | OutputBoundary::TargetStop
            | OutputBoundary::ClientTermination => self.end_context,
        }
    }
}

pub fn response<E>(
    response: &RecordedMysqlResponse<E>,
    row_encoding: ResultRowEncoding,
    status_flags: u16,
) -> ResponseOutput<'_> {
    diagnostics::response_kind(
        match response.status.as_str() {
            "resultset" => "resultset",
            "ok" => "ok",
            _ => "error",
        },
        Some(status_flags),
    );
    if response.status == "resultset" && !response.columns.is_empty() {
        let columns = &response.columns;
        let header = std::iter::once(Ok(Message {
            payload: lenenc_int(columns.len() as u64),
            boundary: OutputBoundary::Headers,
            complete: false,
        }))
        .chain(columns.iter().map(|column| {
            Ok(Message {
                payload: column_definition_payload(column),
                boundary: OutputBoundary::Headers,
                complete: false,
            })
        }))
        .chain(std::iter::once(Ok(Message {
            payload: eof_payload_with_status(status_flags),
            boundary: OutputBoundary::Headers,
            complete: true,
        })));
        let rows = response.rows.iter().map(move |row| {
            let payload = match row_encoding {
                ResultRowEncoding::Text => text_row_payload(row),
                ResultRowEncoding::Binary => binary_row_payload(columns, row),
            }?;
            Ok(Message {
                payload,
                boundary: OutputBoundary::Part,
                complete: true,
            })
        });
        let end = std::iter::once(Ok(Message {
            payload: eof_payload_with_status(status_flags),
            boundary: OutputBoundary::End,
            complete: true,
        }));
        return ResponseOutput::new(
            header.chain(rows).chain(end),
            response.rows.len(),
            "failed to flush MySQL resultset",
        );
    }
    let payload = match response.status.as_str() {
        "ok" => ok_payload_with_status(
            response.affected_rows.unwrap_or_default(),
            response.last_insert_id.unwrap_or_default(),
            status_flags,
        ),
        "error" => err_payload(
            response.error_code.unwrap_or(1105),
            response
                .error_message
                .as_deref()
                .unwrap_or("recorded MySQL dependency error"),
        ),
        "resultset" => err_payload(1105, "recorded resultset has no column metadata"),
        other => err_payload(
            1105,
            &format!("unsupported recorded MySQL response status {other}"),
        ),
    };
    packet(MysqlPacket {
        sequence_id: 1,
        payload,
    })
}

pub fn packet(packet: MysqlPacket) -> ResponseOutput<'static> {
    let sequence = packet.sequence_id;
    let mut output = ResponseOutput::new(
        std::iter::once(Ok(Message {
            payload: packet.payload,
            boundary: OutputBoundary::End,
            complete: true,
        })),
        0,
        "failed to flush MySQL replay packet",
    );
    output.next_sequence = sequence;
    output
}

pub fn prepare(
    statement_id: u32,
    metadata: &StatementMetadata,
    status_flags: u16,
) -> ResponseOutput<'_> {
    diagnostics::response_kind("prepare_ok_and_metadata", Some(status_flags));
    if !diagnostics::active()
        && let Some(bytes) = metadata.encoded(statement_id, status_flags)
    {
        let mut output = ResponseOutput::new(
            std::iter::empty(),
            0,
            "failed to flush MySQL prepare metadata",
        );
        output.cached = Some(bytes.into());
        output.write_context = "failed to write MySQL prepare metadata";
        return output;
    }
    let mut messages = prepare_messages(metadata, statement_id, status_flags).peekable();
    ResponseOutput::new(
        std::iter::from_fn(move || {
            let (payload, _) = messages.next()?;
            Some(Ok(Message {
                payload,
                boundary: OutputBoundary::End,
                complete: messages.peek().is_none(),
            }))
        }),
        0,
        "failed to flush MySQL prepare metadata",
    )
}

#[cfg(test)]
mod tests;
