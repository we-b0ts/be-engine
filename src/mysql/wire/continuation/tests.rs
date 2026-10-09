use super::*;
use crate::mysql::wire::read_packet;

#[tokio::test]
async fn encodes_boundaries_empty_terminators_and_sequence_wrap() {
    for len in [
        0,
        MAX_PACKET_PAYLOAD_LEN - 1,
        MAX_PACKET_PAYLOAD_LEN,
        MAX_PACKET_PAYLOAD_LEN + 1,
        2 * MAX_PACKET_PAYLOAD_LEN,
        19_795_743,
    ] {
        let message = MysqlPacket {
            sequence_id: 255,
            payload: vec![0x61; len],
        };
        let mut wire = Vec::new();
        let next = write_message(&mut wire, &message).await.unwrap();
        let count = len / MAX_PACKET_PAYLOAD_LEN + 1;
        assert_eq!(wire.len(), len + 4 * count);
        assert_eq!(next, 255_u8.wrapping_add(count as u8));
        let mut offset = 0;
        let mut reconstructed = Vec::new();
        for index in 0..count {
            let header = &wire[offset..offset + 4];
            let size = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            assert_eq!(header[3], 255_u8.wrapping_add(index as u8));
            assert_eq!(
                size,
                if index + 1 == count {
                    len % MAX_PACKET_PAYLOAD_LEN
                } else {
                    MAX_PACKET_PAYLOAD_LEN
                }
            );
            reconstructed.extend_from_slice(&wire[offset + 4..offset + 4 + size]);
            offset += 4 + size;
        }
        assert_eq!(offset, wire.len());
        assert_eq!(reconstructed, message.payload);
    }
}

#[test]
fn reassembles_multiple_fragments_and_keeps_the_first_sequence() {
    let mut assembler = MysqlPacketAssembler::default();
    for sequence_id in [254, 255] {
        let packet = MysqlPacket {
            sequence_id,
            payload: vec![sequence_id; MAX_PACKET_PAYLOAD_LEN],
        };
        assert!(assembler.push(&packet).unwrap().is_none());
    }
    let tail = MysqlPacket {
        sequence_id: 0,
        payload: vec![0xff, 0xfe, 0x00],
    };
    let message = assembler.push(&tail).unwrap().unwrap();
    assert_eq!(message.sequence_id, 254);
    assert_eq!(message.payload.len(), 2 * MAX_PACKET_PAYLOAD_LEN + 3);
    assert_eq!(message.payload[0], 254);
    assert_eq!(message.payload[MAX_PACKET_PAYLOAD_LEN], 255);
    assert_eq!(
        &message.payload[2 * MAX_PACKET_PAYLOAD_LEN..],
        &tail.payload
    );
    assembler.finish().unwrap();
    assert!(matches!(
        assembler.push(&tail).unwrap(),
        Some(Cow::Borrowed(_))
    ));
}

#[test]
fn requires_the_empty_terminator_for_an_exact_boundary() {
    let mut assembler = MysqlPacketAssembler::default();
    let packet = MysqlPacket {
        sequence_id: 4,
        payload: vec![0; MAX_PACKET_PAYLOAD_LEN],
    };
    assert!(assembler.push(&packet).unwrap().is_none());
    let tail = MysqlPacket {
        sequence_id: 5,
        payload: Vec::new(),
    };
    assert_eq!(assembler.push(&tail).unwrap().unwrap().as_ref(), &packet);
    assembler.finish().unwrap();
}

#[test]
fn rejects_missing_or_out_of_order_continuations() {
    let packet = MysqlPacket {
        sequence_id: 4,
        payload: vec![0; MAX_PACKET_PAYLOAD_LEN],
    };
    let mut assembler = MysqlPacketAssembler::default();
    assert!(assembler.push(&packet).unwrap().is_none());
    let wrong_sequence = MysqlPacket {
        sequence_id: 6,
        payload: Vec::new(),
    };
    assert_eq!(
        assembler.push(&wrong_sequence).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        assembler.finish().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn distinguishes_clean_eof_from_truncated_physical_packets() {
    assert!(read_packet(&mut &[][..]).await.unwrap().is_none());
    for bytes in [vec![1], vec![1, 0, 0], vec![1, 0, 0, 5]] {
        assert_eq!(
            read_packet(&mut bytes.as_slice()).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
