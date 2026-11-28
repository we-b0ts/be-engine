//! Positional TSV rows in the ordinary and push event journals.
use anyhow::{Context, Result, bail, ensure};
use std::{fmt::Display, io::Write, str::FromStr};
use traffic_model::{
    DependencyTermination, TerminationKind, TerminationScope, TerminationSide,
    recording::{CapturePhase, identity::IdentityKind},
    trace::{CaptureEvent, InputKind, OutputKind, PrimaryBoundary, RecordedEvent},
};
use uuid::Uuid;

trait Token: Sized {
    fn name(self) -> &'static str;
    fn from_token(token: &str) -> Result<Self>;
}

macro_rules! tokens {
    ($ty:ty { $($variant:ident => $name:literal),+ $(,)? }) => {
        impl Token for $ty {
            fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            fn from_token(token: &str) -> Result<Self> {
                match token {
                    $($name => Ok(Self::$variant),)+
                    _ => bail!("invalid {} token {token:?}", stringify!($ty)),
                }
            }
        }
    };
}

#[derive(Clone, Copy)]
enum EventType {
    PrimaryBoundary,
    PrimaryInput,
    CaptureStarted,
    MessageStarted,
    WireOutputStarted,
    WireOutput,
    WireOutputCancelled,
    CaptureTerminated,
    CaptureSealed,
}

tokens!(EventType {
    PrimaryBoundary => "primary_boundary",
    PrimaryInput => "primary_input",
    CaptureStarted => "capture_started",
    MessageStarted => "message_started",
    WireOutputStarted => "wire_output_started",
    WireOutput => "wire_output",
    WireOutputCancelled => "wire_output_cancelled",
    CaptureTerminated => "capture_terminated",
    CaptureSealed => "capture_sealed",
});
tokens!(CapturePhase { Startup => "startup", Runtime => "runtime", Shutdown => "shutdown" });
tokens!(PrimaryBoundary { Start => "start", ResponseEnd => "response_end" });
tokens!(InputKind {
    Request => "request",
    Message => "message",
    Upgrade => "upgrade",
    ClientClose => "client_close",
    TransportEnd => "transport_end",
});
tokens!(TerminationSide { Client => "client", Server => "server", Engine => "engine" });
tokens!(TerminationKind { Eof => "eof", Reset => "reset", Cancelled => "cancelled" });
tokens!(TerminationScope { WriteHalf => "write_half", Connection => "connection", Stream => "stream" });

const ABSENT: &str = "-";

fn write_optional_id(row: &mut Vec<u8>, id: Option<Uuid>, recording_id: Uuid) -> Result<()> {
    match id {
        Some(id) => write!(
            row,
            "\t{}",
            crate::dependency_columns::display_id(IdentityKind::Case, recording_id, id)
        )?,
        None => write!(row, "\t{ABSENT}")?,
    }
    Ok(())
}

fn write_output(row: &mut Vec<u8>, output: OutputKind) -> Result<()> {
    let kind = match output {
        OutputKind::Headers => "headers",
        OutputKind::Part => "part",
        OutputKind::End => "end",
        OutputKind::NoResponse => "no_response",
        OutputKind::TargetStop => "target_stop",
        OutputKind::Terminated { termination } => {
            write!(
                row,
                "\tterminated\t{}\t{}\t{}",
                termination.side.name(),
                termination.kind.name(),
                termination.scope.name()
            )?;
            return Ok(());
        }
    };
    write!(row, "\t{kind}")?;
    Ok(())
}

pub(crate) fn encode_event(
    record: &RecordedEvent<CaptureEvent>,
    recording_id: Uuid,
) -> Result<Vec<u8>> {
    let event_type = match record.event {
        CaptureEvent::PrimaryBoundary { .. } => EventType::PrimaryBoundary,
        CaptureEvent::Input { .. } => EventType::PrimaryInput,
        CaptureEvent::Started { .. } => EventType::CaptureStarted,
        CaptureEvent::MessageStarted { .. } => EventType::MessageStarted,
        CaptureEvent::Bound { .. } => bail!("protocol bindings belong to dependency rows"),
        CaptureEvent::OutputStarted { .. } => EventType::WireOutputStarted,
        CaptureEvent::Output { .. } => EventType::WireOutput,
        CaptureEvent::OutputCancelled { .. } => EventType::WireOutputCancelled,
        CaptureEvent::Terminal { .. } => EventType::CaptureTerminated,
        CaptureEvent::Sealed => EventType::CaptureSealed,
    };
    let mut row = Vec::with_capacity(128);
    write!(
        row,
        "{}\t{}\t{}",
        record.sequence,
        record.offset_micros,
        event_type.name()
    )?;
    match &record.event {
        CaptureEvent::PrimaryBoundary { case_id, boundary } => {
            write_optional_id(&mut row, Some(*case_id), recording_id)?;
            write!(row, "\t{}", boundary.name())?;
        }
        CaptureEvent::Input {
            case_id,
            input_sequence,
            kind,
        } => {
            write_optional_id(&mut row, Some(*case_id), recording_id)?;
            write!(row, "\t{input_sequence}\t{}", kind.name())?;
        }
        CaptureEvent::Started {
            dependency_sequence,
            phase,
            observed_case,
            admitted_case,
        } => {
            ensure!(
                *dependency_sequence == record.sequence,
                "dependency start must own its event sequence"
            );
            write!(row, "\t{}", phase.name())?;
            write_optional_id(&mut row, *observed_case, recording_id)?;
            write_optional_id(&mut row, *admitted_case, recording_id)?;
        }
        CaptureEvent::MessageStarted {
            dependency_sequence,
        } => {
            ensure!(
                *dependency_sequence == record.sequence,
                "notification start must own its event sequence"
            );
        }
        CaptureEvent::Bound { .. } => unreachable!("binding events are rejected above"),
        CaptureEvent::OutputStarted {
            dependency_sequence,
            output,
        }
        | CaptureEvent::Output {
            dependency_sequence,
            output,
        } => {
            write!(row, "\t{dependency_sequence}")?;
            write_output(&mut row, *output)?;
        }
        CaptureEvent::OutputCancelled {
            dependency_sequence,
            started_sequence,
        } => {
            write!(row, "\t{dependency_sequence}\t{started_sequence}")?;
        }
        CaptureEvent::Terminal {
            dependency_sequence,
            outcome,
            capture_complete,
        } => {
            write!(row, "\t{dependency_sequence}\t")?;
            // Preserve free-form outcomes without letting them split a cell or row.
            if outcome.starts_with('"') || outcome.contains(['\t', '\n', '\r']) {
                serde_json::to_writer(&mut row, outcome)?;
            } else {
                row.extend_from_slice(outcome.as_bytes());
            }
            write!(row, "\t{}", u8::from(*capture_complete))?;
        }
        CaptureEvent::Sealed => {}
    }
    row.push(b'\n');
    Ok(row)
}

struct Columns<'a>(std::str::Split<'a, char>);

impl<'a> Columns<'a> {
    fn field(&mut self, name: &str) -> Result<&'a str> {
        self.0
            .next()
            .with_context(|| format!("missing event {name}"))
    }

    fn parse<T: FromStr>(&mut self, name: &str) -> Result<T>
    where
        T::Err: Display,
    {
        self.field(name)?
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid event {name}: {error}"))
    }

    fn token<T: Token>(&mut self, name: &str) -> Result<T> {
        T::from_token(self.field(name)?)
    }

    fn optional_id(&mut self, name: &str, recording_id: Uuid) -> Result<Option<Uuid>> {
        match self.field(name)? {
            ABSENT => Ok(None),
            id => Ok(Some(crate::dependency_columns::parse_id(
                IdentityKind::Case,
                recording_id,
                id,
            )?)),
        }
    }

    fn output(&mut self) -> Result<OutputKind> {
        match self.field("output kind")? {
            "headers" => Ok(OutputKind::Headers),
            "part" => Ok(OutputKind::Part),
            "end" => Ok(OutputKind::End),
            "no_response" => Ok(OutputKind::NoResponse),
            "target_stop" => Ok(OutputKind::TargetStop),
            "terminated" => Ok(OutputKind::Terminated {
                termination: DependencyTermination {
                    side: self.token("termination side")?,
                    kind: self.token("termination kind")?,
                    scope: self.token("termination scope")?,
                },
            }),
            kind => bail!("invalid event output kind {kind:?}"),
        }
    }
}

pub(crate) fn decode_event(row: &str, recording_id: Uuid) -> Result<RecordedEvent<CaptureEvent>> {
    let row = row.strip_suffix('\n').unwrap_or(row);
    let row = row.strip_suffix('\r').unwrap_or(row);
    let mut columns = Columns(row.split('\t'));
    let sequence = columns.parse("sequence")?;
    let offset_micros = columns.parse("offset")?;
    let event_type = columns.token("type")?;
    let event = match event_type {
        EventType::PrimaryBoundary => CaptureEvent::PrimaryBoundary {
            case_id: columns
                .optional_id("case ID", recording_id)?
                .context("missing case ID")?,
            boundary: columns.token("boundary")?,
        },
        EventType::PrimaryInput => CaptureEvent::Input {
            case_id: columns
                .optional_id("case ID", recording_id)?
                .context("missing case ID")?,
            input_sequence: columns.parse("input sequence")?,
            kind: columns.token("input kind")?,
        },
        EventType::CaptureStarted => CaptureEvent::Started {
            dependency_sequence: sequence,
            phase: columns.token("phase")?,
            observed_case: columns.optional_id("observed case", recording_id)?,
            admitted_case: columns.optional_id("admitted case", recording_id)?,
        },
        EventType::MessageStarted => CaptureEvent::MessageStarted {
            dependency_sequence: sequence,
        },
        EventType::WireOutputStarted | EventType::WireOutput => {
            let dependency_sequence = columns.parse("dependency sequence")?;
            let output = columns.output()?;
            match event_type {
                EventType::WireOutputStarted => CaptureEvent::OutputStarted {
                    dependency_sequence,
                    output,
                },
                _ => CaptureEvent::Output {
                    dependency_sequence,
                    output,
                },
            }
        }
        EventType::WireOutputCancelled => CaptureEvent::OutputCancelled {
            dependency_sequence: columns.parse("dependency sequence")?,
            started_sequence: columns.parse("cancelled output sequence")?,
        },
        EventType::CaptureTerminated => {
            let dependency_sequence = columns.parse("dependency sequence")?;
            let outcome = columns.field("outcome")?;
            let outcome = if outcome.starts_with('"') {
                serde_json::from_str(outcome)?
            } else {
                outcome.to_owned()
            };
            let capture_complete = match columns.field("capture completeness")? {
                "1" => true,
                "0" => false,
                value => bail!("invalid event capture completeness {value:?}"),
            };
            CaptureEvent::Terminal {
                dependency_sequence,
                outcome,
                capture_complete,
            }
        }
        EventType::CaptureSealed => CaptureEvent::Sealed,
    };
    ensure!(columns.0.next().is_none(), "unexpected extra event columns");
    Ok(RecordedEvent {
        sequence,
        offset_micros,
        event,
    })
}

pub(crate) fn decode_stream_event(
    row: &[u8],
    recording_id: Uuid,
) -> Result<Option<RecordedEvent<CaptureEvent>>> {
    let mut columns = row.split(|byte| *byte == b'\t');
    let kind = columns
        .nth(2)
        .context("missing recording stream row type")?;
    match kind {
        b"request" | b"response" | b"message" | b"observation" | b"dependency"
        | b"notification" => Ok(None),
        _ => decode_event(std::str::from_utf8(row)?, recording_id).map(Some),
    }
}

#[cfg(test)]
mod tests;
