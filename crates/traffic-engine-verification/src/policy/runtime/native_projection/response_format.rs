//! Response timestamp compatibility representations.
use crate::policy::TimestampFormat;
use anyhow::Result;

pub(super) fn project(
    value: TimestampFormat,
) -> Result<super::super::response::ResponseTimestampFormat> {
    Ok(match value {
        TimestampFormat::UnixSeconds => {
            super::super::response::ResponseTimestampFormat::UnixSeconds
        }
        TimestampFormat::UnixMilliseconds => {
            super::super::response::ResponseTimestampFormat::UnixMilliseconds
        }
        TimestampFormat::Rfc3339 => super::super::response::ResponseTimestampFormat::Rfc3339,
        TimestampFormat::AmzDate => super::super::response::ResponseTimestampFormat::AmzDate,
        _ => anyhow::bail!("timestamp format is unsupported by this response domain"),
    })
}
