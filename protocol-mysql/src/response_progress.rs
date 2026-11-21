//! Logical result boundaries, independent of packet fragmentation and I/O.
use crate::{MysqlPacket, parse_server_packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBoundary {
    Headers,
    Row,
}

pub struct ResponseProgress {
    phase: Phase,
}

enum Phase {
    First,
    Columns,
    Rows,
    Finished,
}

impl ResponseProgress {
    pub fn new(command: &str) -> Self {
        Self {
            phase: if command == "COM_STMT_PREPARE" {
                Phase::Finished
            } else {
                Phase::First
            },
        }
    }

    /// Accept a reassembled logical message. Column definitions form a single
    /// header boundary, so SQL projection changes never add delivery barriers.
    pub fn observe(&mut self, message: &MysqlPacket) -> Option<ResponseBoundary> {
        let kind = parse_server_packet(message).kind;
        if kind == "error" {
            self.phase = Phase::Finished;
            return None;
        }
        match self.phase {
            Phase::First => {
                self.phase = if matches!(kind.as_str(), "ok" | "eof") {
                    Phase::Finished
                } else {
                    Phase::Columns
                };
                None
            }
            Phase::Columns if kind == "eof" => {
                self.phase = Phase::Rows;
                Some(ResponseBoundary::Headers)
            }
            Phase::Rows if kind == "eof" => {
                self.phase = Phase::Finished;
                None
            }
            Phase::Rows => Some(ResponseBoundary::Row),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_count_and_binary_row_tags_do_not_change_logical_boundaries() {
        let mut progress = ResponseProgress::new("COM_STMT_EXECUTE");
        let observed: Vec<_> = [
            vec![2],
            b"column1".to_vec(),
            b"column2".to_vec(),
            vec![0xfe, 0, 0, 0, 0],
            vec![0x00, 0x00, 42],
            vec![0x00, 0x00, 43],
            vec![0xfe, 0, 0, 0, 0],
        ]
        .into_iter()
        .filter_map(|payload| {
            progress.observe(&MysqlPacket {
                sequence_id: 1,
                payload,
            })
        })
        .collect();
        assert_eq!(
            observed,
            [
                ResponseBoundary::Headers,
                ResponseBoundary::Row,
                ResponseBoundary::Row
            ]
        );
    }
}
