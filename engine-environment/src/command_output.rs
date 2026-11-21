use std::fmt::Arguments;
use std::io::{self, Write};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Debug, Clone, Copy, Default)]
pub struct TracingWriter;

impl<'writer> MakeWriter<'writer> for TracingWriter {
    type Writer = BrokenPipeSafeWriter<io::Stdout>;

    fn make_writer(&'writer self) -> Self::Writer {
        BrokenPipeSafeWriter::new(io::stdout())
    }
}

pub fn stdout(arguments: Arguments<'_>) -> Result<()> {
    write_output(
        &mut BrokenPipeSafeWriter::new(io::stdout().lock()),
        arguments,
    )
    .context("failed to write CLI output")
}

pub fn stdout_line(arguments: Arguments<'_>) -> Result<()> {
    write_output_line(
        &mut BrokenPipeSafeWriter::new(io::stdout().lock()),
        arguments,
    )
    .context("failed to write CLI output")
}

pub fn stderr_line(arguments: Arguments<'_>) {
    let _ = write_output_line(
        &mut BrokenPipeSafeWriter::new(io::stderr().lock()),
        arguments,
    );
}

pub struct BrokenPipeSafeWriter<W> {
    inner: W,
    closed: bool,
}

impl<W> BrokenPipeSafeWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            closed: false,
        }
    }
}

impl<W: Write> Write for BrokenPipeSafeWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(buffer.len());
        }
        match self.inner.write(buffer) {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(buffer.len())
            }
            result => result,
        }
    }

    fn write_all(&mut self, buffer: &[u8]) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.write_all(buffer) {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(())
            }
            result => result,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        match self.inner.flush() {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.closed = true;
                Ok(())
            }
            result => result,
        }
    }
}

fn write_output(writer: &mut impl Write, arguments: Arguments<'_>) -> io::Result<()> {
    write!(writer, "{arguments}")
}

fn write_output_line(writer: &mut impl Write, arguments: Arguments<'_>) -> io::Result<()> {
    writeln!(writer, "{arguments}")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    struct FailedWriter;

    impl Write for FailedWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    #[test]
    fn closed_pipe_accepts_further_output_and_flushes() {
        let mut writer = BrokenPipeSafeWriter::new(BrokenPipeWriter);

        assert!(writer.write_all(b"shutdown").is_ok());
        assert!(writer.write_all(b"cleanup").is_ok());
        assert!(writer.flush().is_ok());
    }

    #[test]
    fn non_pipe_output_errors_are_preserved() {
        let mut writer = BrokenPipeSafeWriter::new(FailedWriter);

        let error = writer.write_all(b"shutdown").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
