//! Source-derived read states; optional nil never authorizes a write or value.
use super::*;

/// A read-only key can be observed absent, or reach one stable terminal value.
/// Actual DEL boundaries remain finite, including multi-key cleanup.
pub(super) fn read_only(
    mut profile: Profile,
    timeline: &[(usize, &ReplayExchange)],
) -> Result<Profile> {
    let mut lanes = BTreeMap::new();
    let mut reads: Vec<&ReplayExchange> = Vec::new();
    let mut value: Option<Vec<u8>> = None;
    let mut mutation: Option<&ReplayExchange> = None;
    let mut observed = false;
    for &(index, exchange) in timeline {
        if let Some(previous) =
            lanes.insert(exchange.record.connection_id, exchange.record.sequence)
        {
            ensure!(
                previous < exchange.record.sequence,
                "state read Source clocks reverse a connection lane"
            );
        }
        let response = exchange.response_bytes()?;
        ensure!(
            response.len() <= crate::value_limits::MAX_VALUE_BYTES,
            "state read response exceeds bounds"
        );
        if let Some(before) = mutation {
            source::require_causal_order(before, exchange)?;
        }
        match exchange.record.command.as_str() {
            "GET" => {
                ensure!(
                    exchange.args == [profile.key.clone()],
                    "state observation requires single-key GET"
                );
                ensure!(
                    matches!(
                        redis_frame_kind(&bytes::Bytes::copy_from_slice(&response))?,
                        RedisFrameKind::Null | RedisFrameKind::BulkString
                    ),
                    "state GET must have a complete nil or bulk response"
                );
                if let Some(previous) = &value
                    && *previous != response
                {
                    ensure!(
                        profile.transient_nil && previous == b"$-1\r\n" && response != b"$-1\r\n",
                        "read-only state changed without a supported SET; only a declared transient nil may precede a stable terminal value"
                    );
                    for before in &reads {
                        source::require_causal_order(before, exchange)?;
                    }
                    ensure!(
                        profile.epochs.len() < 1024,
                        "state observation epoch limit exceeded"
                    );
                    let gate = profile.epochs.last().unwrap().mutation;
                    profile.epochs.push(Epoch {
                        mutation: gate,
                        observations: vec![],
                    });
                    reads.clear();
                }
                value = Some(response);
                reads.push(exchange);
                observed = true;
                profile.epochs.last_mut().unwrap().observations.push(index);
            }
            "DEL" | "UNLINK" => {
                for before in &reads {
                    source::require_causal_order(before, exchange)?;
                }
                let removed = source::integer(&response)?;
                let unique = exchange.args.iter().collect::<BTreeSet<_>>().len();
                let known_absent = value.as_deref() == Some(b"$-1\r\n");
                let upper = unique.saturating_sub(usize::from(known_absent));
                ensure!(
                    usize::try_from(removed).is_ok_and(|n| n <= upper),
                    "state cleanup count contradicts the observed key state"
                );
                if value.is_some() && !known_absent {
                    ensure!(
                        removed > 0,
                        "state cleanup did not remove the observed existing key"
                    );
                }
                source::new_epoch(&mut profile, index)?;
                value = Some(b"$-1\r\n".to_vec());
                reads.clear();
                mutation = Some(exchange);
            }
            _ => anyhow::bail!(
                "state observation has an unsupported writer or expiry observer; preserve finite matching or declare its typed state effect"
            ),
        }
    }
    ensure!(
        observed,
        "state observation has no original Source GET witness"
    );
    Ok(profile)
}
