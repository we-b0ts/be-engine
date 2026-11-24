//! Typed physical rows. Protocol cells are kept encoded until their consumer needs them.
use std::{borrow::Cow, io::Write, num::NonZeroU64};

use anyhow::{Context, Result, ensure};
use traffic_model::recording::identity::IdentityKind;
use uuid::Uuid;

use crate::dependency_columns::valid_response_literal_name;

use super::{PayloadRef, atoms};

pub(crate) const COLUMN_COUNT: usize = 11;

#[derive(Debug)]
pub(crate) enum Optional<T> {
    Absent,
    Null,
    Present(T),
}

impl<T> Optional<T> {
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Optional<U> {
        match self {
            Self::Absent => Optional::Absent,
            Self::Null => Optional::Null,
            Self::Present(value) => Optional::Present(f(value)),
        }
    }

    pub(crate) fn try_map<U>(self, f: impl FnOnce(T) -> Result<U>) -> Result<Optional<U>> {
        Ok(match self {
            Self::Absent => Optional::Absent,
            Self::Null => Optional::Null,
            Self::Present(value) => Optional::Present(f(value)?),
        })
    }

    fn write(
        &self,
        out: &mut Vec<u8>,
        present: impl FnOnce(&mut Vec<u8>, &T) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Absent => out.push(b'-'),
            Self::Null => out.push(b'~'),
            Self::Present(value) => present(out, value)?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct DependencyPrefix<'a> {
    pub sequence: NonZeroU64,
    pub protocol: Optional<Cow<'a, str>>,
    pub case: Optional<Uuid>,
    pub target: Optional<Cow<'a, str>>,
    pub client: Optional<Cow<'a, str>>,
    pub upstream: Optional<Cow<'a, str>>,
    pub connection: Optional<Uuid>,
    pub duration_ms: Optional<u64>,
}

#[derive(Debug)]
pub(crate) struct ProtocolExtension<'a> {
    pub variant: Option<&'a str>,
    pub fields: &'a str,
    pub metadata: &'a str,
}

impl<'a> ProtocolExtension<'a> {
    pub fn parse(cell: &'a str) -> Result<Self> {
        let extension = cell
            .strip_prefix("ext:")
            .context("invalid dependency extension")?;
        if let Some(metadata) = extension.strip_prefix('-') {
            return Ok(Self {
                variant: None,
                fields: "",
                metadata,
            });
        }
        let (variant, extension) = extension
            .split_once('[')
            .context("missing dependency extension fields")?;
        let variant = if variant.is_empty() {
            ""
        } else {
            variant
                .strip_suffix(':')
                .context("invalid dependency variant")?
        };
        let (fields, metadata) = extension
            .split_once(']')
            .context("unclosed dependency extension")?;
        Ok(Self {
            variant: Some(variant),
            fields,
            metadata,
        })
    }
}

#[derive(Debug)]
pub(crate) enum PayloadCell<'a> {
    Absent,
    Text(&'a str),
    Base64(&'a str),
    Json(&'a str),
    Literal(&'a str),
    External {
        kind: ExternalKind,
        reference: PayloadRef,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ExternalKind {
    Bytes,
    Text,
    Json,
    JsonFields,
}

impl ExternalKind {
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Bytes => "path",
            Self::Text => "path-text",
            Self::Json => "json-path",
            Self::JsonFields => "fields-path",
        }
    }
}

impl<'a> PayloadCell<'a> {
    pub fn parse(cell: &'a str) -> Result<Self> {
        if cell == "-" {
            return Ok(Self::Absent);
        }
        let (tag, bytes) = cell
            .split_once(':')
            .context("missing dependency payload encoding")?;
        Ok(match tag {
            "text" => Self::Text(bytes),
            "b64" => Self::Base64(bytes),
            "json" => Self::Json(bytes),
            "const" => {
                ensure!(
                    valid_response_literal_name(bytes),
                    "invalid response literal name"
                );
                Self::Literal(bytes)
            }
            "path" | "path-text" | "json-path" | "fields-path" => Self::External {
                kind: match tag {
                    "path" => ExternalKind::Bytes,
                    "path-text" => ExternalKind::Text,
                    "json-path" => ExternalKind::Json,
                    _ => ExternalKind::JsonFields,
                },
                reference: bytes.parse()?,
            },
            _ => anyhow::bail!("unknown dependency payload encoding"),
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Absent => out.push(b'-'),
            Self::Text(value) => {
                out.extend_from_slice(b"text:");
                out.extend_from_slice(value.as_bytes());
            }
            Self::Base64(value) => {
                out.extend_from_slice(b"b64:");
                out.extend_from_slice(value.as_bytes());
            }
            Self::Json(value) => {
                out.extend_from_slice(b"json:");
                out.extend_from_slice(value.as_bytes());
            }
            Self::Literal(name) => {
                ensure!(
                    valid_response_literal_name(name),
                    "invalid response literal name"
                );
                out.extend_from_slice(b"const:");
                out.extend_from_slice(name.as_bytes());
            }
            Self::External { kind, reference } => {
                write!(
                    out,
                    "{}:{}:{}:{}",
                    kind.tag(),
                    reference.segment,
                    reference.offset,
                    reference.length
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct DependencyRow<'a> {
    pub prefix: DependencyPrefix<'a>,
    pub extension: ProtocolExtension<'a>,
    pub request: PayloadCell<'a>,
    pub response: PayloadCell<'a>,
}

impl<'a> DependencyRow<'a> {
    pub(crate) fn parse(row: &'a [u8], epoch: Uuid) -> Result<Self> {
        let row = std::str::from_utf8(row)?;
        let mut cells = row.strip_suffix('\n').unwrap_or(row).split('\t');
        let columns: [Option<&str>; COLUMN_COUNT] = std::array::from_fn(|_| cells.next());
        let [
            Some(sequence),
            Some(protocol),
            Some(case),
            Some(target),
            Some(client),
            Some(upstream),
            Some(connection),
            Some(duration),
            Some(ext),
            Some(request),
            Some(response),
        ] = columns
        else {
            anyhow::bail!("invalid compact dependency row");
        };
        ensure!(cells.next().is_none(), "unexpected dependency column");
        Ok(Self {
            prefix: DependencyPrefix {
                sequence: sequence.parse()?,
                protocol: read_text(protocol)?,
                case: read_id(case, epoch, IdentityKind::Case)?,
                target: read_text(target)?,
                client: read_text(client)?,
                upstream: read_text(upstream)?,
                connection: read_id(connection, epoch, IdentityKind::Connection)?,
                duration_ms: match duration {
                    "-" => Optional::Absent,
                    "~" => Optional::Null,
                    duration => Optional::Present(duration.parse()?),
                },
            },
            extension: ProtocolExtension::parse(ext)?,
            request: PayloadCell::parse(request)?,
            response: PayloadCell::parse(response)?,
        })
    }

    pub(crate) fn write(
        prefix: &DependencyPrefix<'_>,
        extension: ProtocolExtension<'_>,
        request: PayloadCell<'_>,
        response: PayloadCell<'_>,
        epoch: Uuid,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(192);
        write!(out, "{}\t", prefix.sequence)?;
        let write_text = |out: &mut Vec<u8>, value: &Cow<'_, str>| {
            atoms::text(out, value);
            Ok(())
        };
        let write_id = |kind: IdentityKind, out: &mut Vec<u8>, id: &Uuid| {
            atoms::text(out, &kind.display(epoch, *id));
            Ok(())
        };
        prefix.protocol.write(&mut out, write_text)?;
        out.push(b'\t');
        prefix
            .case
            .write(&mut out, |out, id| write_id(IdentityKind::Case, out, id))?;
        out.push(b'\t');
        for address in [&prefix.target, &prefix.client, &prefix.upstream] {
            address.write(&mut out, write_text)?;
            out.push(b'\t');
        }
        prefix.connection.write(&mut out, |out, id| {
            write_id(IdentityKind::Connection, out, id)
        })?;
        out.push(b'\t');
        prefix
            .duration_ms
            .write(&mut out, |out, ms| Ok(write!(out, "{ms}")?))?;
        out.push(b'\t');
        out.extend_from_slice(b"ext:");
        if let Some(variant) = extension.variant {
            if !variant.is_empty() {
                out.extend_from_slice(variant.as_bytes());
                out.push(b':');
            }
            out.push(b'[');
            out.extend_from_slice(extension.fields.as_bytes());
            out.push(b']');
        } else {
            out.push(b'-');
        }
        out.extend_from_slice(extension.metadata.as_bytes());
        out.push(b'\t');
        request.write(&mut out)?;
        out.push(b'\t');
        response.write(&mut out)?;
        out.push(b'\n');
        Ok(out)
    }
}

fn read_text(value: &str) -> Result<Optional<Cow<'_, str>>> {
    Ok(match value {
        "-" => Optional::Absent,
        "~" => Optional::Null,
        value if value.contains('%') => Optional::Present(Cow::Owned(atoms::untext(value)?)),
        value => Optional::Present(Cow::Borrowed(value)),
    })
}

fn read_id(value: &str, epoch: Uuid, kind: IdentityKind) -> Result<Optional<Uuid>> {
    read_text(value)?.try_map(|label| {
        kind.parse(epoch, &label)
            .context("invalid recording-local ID")
    })
}
