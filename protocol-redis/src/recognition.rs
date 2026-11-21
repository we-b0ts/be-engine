//! Identify the first RESP command without buffering or decoding its value arguments.
use traffic_protocol::{Peer, Probe, Recognition};

pub fn recognize(probe: Probe<'_>) -> Recognition {
    if probe.peer != Peer::Client {
        return Recognition::Reject;
    }
    let bytes = probe.bytes;
    if bytes.is_empty() {
        return Recognition::NeedMore;
    }
    if bytes[0] != b'*' {
        return Recognition::Reject;
    }
    let Some(end) = line_end(bytes) else {
        return Recognition::NeedMore;
    };
    if number(&bytes[1..end]).is_none_or(|count| count == 0) {
        return Recognition::Reject;
    }
    let command = &bytes[end + 2..];
    let Some(first) = command.first() else {
        return Recognition::NeedMore;
    };
    let Some(end) = line_end(command) else {
        return Recognition::NeedMore;
    };
    let name = match first {
        b'+' => &command[1..end],
        b'$' => {
            let Some(length) = number(&command[1..end]).filter(|length| *length > 0) else {
                return Recognition::Reject;
            };
            let Some(end_name) = (end + 2).checked_add(length) else {
                return Recognition::Reject;
            };
            let Some(end_frame) = end_name.checked_add(2) else {
                return Recognition::Reject;
            };
            if command.len() < end_frame {
                return Recognition::NeedMore;
            }
            if command[end_name..end_frame] != *b"\r\n" {
                return Recognition::Reject;
            }
            &command[end + 2..end_name]
        }
        _ => return Recognition::Reject,
    };
    if !name.is_empty() && name.iter().all(u8::is_ascii_graphic) {
        Recognition::Match
    } else {
        Recognition::Reject
    }
}

fn line_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|pair| pair == b"\r\n")
}

fn number(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0_usize, |number, digit| {
        number
            .checked_mul(10)?
            .checked_add(usize::from(*digit - b'0'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_large_commands_from_the_command_prefix_without_their_payload() {
        let prefix = b"*3\r\n$3\r\nSET\r\n";
        for length in 0..prefix.len() {
            assert_eq!(
                recognize(Probe {
                    peer: Peer::Client,
                    bytes: &prefix[..length]
                }),
                Recognition::NeedMore
            );
        }
        assert_eq!(
            recognize(Probe {
                peer: Peer::Client,
                bytes: prefix
            }),
            Recognition::Match
        );
        for invalid in [b"*0\r\n".as_slice(), b"*-1\r\n", b"*1\r\n$3\r\nG T\r\n"] {
            assert_eq!(
                recognize(Probe {
                    peer: Peer::Client,
                    bytes: invalid
                }),
                Recognition::Reject
            );
        }
    }
}
