use std::borrow::Cow;
use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::MysqlPacket;

pub const MAX_PACKET_PAYLOAD_LEN: usize = 0x00ff_ffff;

/// Reassembles physical packets without changing capture or forwarding bytes.
#[derive(Default)]
pub struct MysqlPacketAssembler {
    pending: Option<MysqlPacket>,
    next_sequence_id: u8,
}

impl MysqlPacketAssembler {
    pub fn push<'a>(
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

    pub fn finish(&mut self) -> io::Result<()> {
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
pub async fn write_message<W>(writer: &mut W, packet: &MysqlPacket) -> io::Result<u8>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut sequence_id = packet.sequence_id;
    for (header, payload) in message_frames(packet) {
        writer.write_all(&header).await?;
        writer.write_all(payload).await?;
        sequence_id = header[3].wrapping_add(1);
    }
    Ok(sequence_id)
}

/// Encode the same physical frames supplied to the asynchronous native writer.
pub fn encode_message(packet: &MysqlPacket) -> io::Result<(bytes::Bytes, u8)> {
    let frames = packet.payload.len() / MAX_PACKET_PAYLOAD_LEN + 1;
    let capacity = frames
        .checked_mul(4)
        .and_then(|headers| packet.payload.len().checked_add(headers))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MySQL message size overflow"))?;
    let mut wire = Vec::with_capacity(capacity);
    let mut next_sequence = packet.sequence_id;
    for (header, payload) in message_frames(packet) {
        wire.extend_from_slice(&header);
        wire.extend_from_slice(payload);
        next_sequence = header[3].wrapping_add(1);
    }
    Ok((wire.into(), next_sequence))
}

fn message_frames(packet: &MysqlPacket) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    packet
        .payload
        .chunks(MAX_PACKET_PAYLOAD_LEN)
        // Exact multiples need an empty physical packet to end the message.
        .chain(
            packet
                .payload
                .len()
                .is_multiple_of(MAX_PACKET_PAYLOAD_LEN)
                .then_some(&[][..]),
        )
        .enumerate()
        .map(|(index, payload)| {
            let length = payload.len();
            let sequence = packet.sequence_id.wrapping_add(index as u8);
            (
                [
                    length as u8,
                    (length >> 8) as u8,
                    (length >> 16) as u8,
                    sequence,
                ],
                payload,
            )
        })
}

#[cfg(test)]
mod tests;
