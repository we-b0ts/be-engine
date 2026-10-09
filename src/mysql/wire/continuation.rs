use std::borrow::Cow;
use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::MysqlPacket;

pub(crate) const MAX_PACKET_PAYLOAD_LEN: usize = 0x00ff_ffff;

/// Reassembles physical packets without changing capture or forwarding bytes.
#[derive(Default)]
pub(crate) struct MysqlPacketAssembler {
    pending: Option<MysqlPacket>,
    next_sequence_id: u8,
}

impl MysqlPacketAssembler {
    pub(crate) fn push<'a>(
        &mut self,
        packet: &'a MysqlPacket,
    ) -> io::Result<Option<Cow<'a, MysqlPacket>>> {
        if packet.payload.len() > MAX_PACKET_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MySQL physical packet exceeds its three-byte length",
            ));
        }
        if let Some(pending) = &mut self.pending {
            if packet.sequence_id != self.next_sequence_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MySQL continuation packet sequence mismatch",
                ));
            }
            pending.payload.extend_from_slice(&packet.payload);
            self.next_sequence_id = packet.sequence_id.wrapping_add(1);
            if packet.payload.len() < MAX_PACKET_PAYLOAD_LEN {
                return Ok(self.pending.take().map(Cow::Owned));
            }
        } else if packet.payload.len() == MAX_PACKET_PAYLOAD_LEN {
            self.pending = Some(packet.clone());
            self.next_sequence_id = packet.sequence_id.wrapping_add(1);
        } else {
            return Ok(Some(Cow::Borrowed(packet)));
        }
        Ok(None)
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.pending.take().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MySQL continuation packet ended before its terminating packet",
            ));
        }
        Ok(())
    }
}

/// Writes one logical message and returns the next physical packet sequence ID.
pub(crate) async fn write_message<W>(writer: &mut W, packet: &MysqlPacket) -> io::Result<u8>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut sequence_id = packet.sequence_id;
    let mut remaining = packet.payload.as_slice();
    loop {
        let len = remaining.len().min(MAX_PACKET_PAYLOAD_LEN);
        let header = [len as u8, (len >> 8) as u8, (len >> 16) as u8, sequence_id];
        writer.write_all(&header).await?;
        writer.write_all(&remaining[..len]).await?;
        sequence_id = sequence_id.wrapping_add(1);
        remaining = &remaining[len..];
        // Exact multiples need an empty packet to terminate the logical message.
        if len < MAX_PACKET_PAYLOAD_LEN {
            return Ok(sequence_id);
        }
    }
}

#[cfg(test)]
mod tests;
