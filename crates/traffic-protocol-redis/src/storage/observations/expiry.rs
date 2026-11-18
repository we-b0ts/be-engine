//! Native SET/GET/DEL intervals that prove a complete TTL lifetime.
use super::*;
use std::time::Duration;
#[derive(Debug)]
pub struct ExpiryProof {
    pub epoch: usize,
    pub creation: usize,
    pub deletion: usize,
    pub required: Vec<usize>,
    pub ttl: Duration,
}
pub(super) fn prove<E: StorageExchange, L>(
    exchanges: &[E],
    profile: &Profile<L>,
    trace: &[usize],
) -> Vec<ExpiryProof> {
    if trace.len() > MAX_OBSERVATIONS {
        return vec![];
    }
    let positions = trace
        .iter()
        .enumerate()
        .map(|(p, &i)| (i, p))
        .collect::<BTreeMap<_, _>>();
    profile
        .epochs
        .windows(2)
        .enumerate()
        .filter_map(|(epoch, pair)| {
            let (creation, deletion) = pair[0].mutation.zip(pair[1].mutation)?;
            let first = &exchanges[creation];
            let last = &exchanges[deletion];
            // Multi-key DEL's aggregate count cannot prove this particular key existed.
            if first.native_record().command != "SET"
                || first.arguments().len() != 4
                || !matches!(last.native_record().command.as_str(), "DEL" | "UNLINK")
                || last.arguments() != [profile.key.clone()]
                || last.response_bytes().ok()? != b":1\r\n"
            {
                return None;
            }
            let ttl = set_ttl(first.arguments())?;
            let elapsed = last
                .native_record()
                .timestamp?
                .signed_duration_since(first.native_record().earliest_start()?)
                .to_std()
                .ok()?;
            if elapsed >= ttl {
                return None;
            }
            let start = *positions.get(&creation)?;
            let end = *positions.get(&deletion)?;
            if end < start || end - start >= MAX_OBSERVATIONS {
                return None;
            }
            let mut expected = format!("${}\r\n", first.arguments()[1].len()).into_bytes();
            expected.extend_from_slice(&first.arguments()[1]);
            expected.extend_from_slice(b"\r\n");
            let mut required = vec![creation];
            for &index in &trace[start + 1..end] {
                let exchange = &exchanges[index];
                match exchange.native_record().command.as_str() {
                    "EXPIRE"
                        if exchange.arguments().len() == 2
                            && seconds(&exchange.arguments()[1]).map(Duration::from_secs)
                                == Some(ttl) => {}
                    "GET"
                        if exchange.arguments() == [profile.key.clone()]
                            && exchange.response_bytes().ok()? == expected =>
                    {
                        required.push(index)
                    }
                    // Changed values, compound reads and other writes need their own proof.
                    _ => return None,
                }
            }
            required.push(deletion);
            Some(ExpiryProof {
                epoch,
                creation,
                deletion,
                required,
                ttl,
            })
        })
        .collect()
}

fn seconds(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value)
        .ok()?
        .parse()
        .ok()
        .filter(|&n| n > 0)
}

pub fn set_ttl(args: &[Vec<u8>]) -> Option<Duration> {
    let value = seconds(args.get(3)?)?;
    if args.get(2)?.eq_ignore_ascii_case(b"EX") {
        Some(Duration::from_secs(value))
    } else if args.get(2)?.eq_ignore_ascii_case(b"PX") && value % 1000 == 0 {
        Some(Duration::from_millis(value))
    } else {
        None
    }
}
