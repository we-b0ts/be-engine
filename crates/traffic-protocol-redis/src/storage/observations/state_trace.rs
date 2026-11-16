//! Source-derived read states; optional nil never authorizes a write or value.
use super::*;

/// A read-only key can be observed absent, or reach one stable terminal value.
/// Actual DEL boundaries remain finite, including multi-key cleanup.
pub(super) fn read_only<E: StorageExchange, L>(
    exchanges: &[E],
    mut profile: Profile<L>,
    timeline: &[(usize, &E)],
) -> Result<Profile<L>> {
    let mut lanes = BTreeMap::new();
    // Keep the entire unchanged-state frontier, including no-op deletions.
    // A long read or cleanup must not disappear behind a shorter later read
    // when checking a real transition to a different value.
    let mut accesses: Vec<&E> = Vec::new();
    let mut value: Option<Vec<u8>> = None;
    let mut mutation: Option<&E> = None;
    let mut observed = false;
    let multiple_lanes = timeline.first().is_some_and(|(_, first)| {
        timeline
            .iter()
            .any(|(_, e)| e.native_record().connection_id != first.native_record().connection_id)
    });
    for &(index, exchange) in timeline {
        if let Some(previous) = lanes.insert(
            exchange.native_record().connection_id,
            exchange.native_record().sequence,
        ) {
            ensure!(
                previous < exchange.native_record().sequence,
                "state read Source clocks reverse a connection lane"
            );
        }
        if multiple_lanes {
            ensure!(
                exchange
                    .native_record()
                    .earliest_start()
                    .zip(exchange.native_record().timestamp)
                    .is_some_and(|(start, end)| start <= end),
                "concurrent state observations require complete Source clocks"
            );
        }
        let response = exchange.response_bytes()?;
        ensure!(
            response.len() <= traffic_value::MAX_VALUE_BYTES,
            "state read response exceeds bounds"
        );
        if let Some(before) = mutation {
            super::require_causal_order(before, exchange)?;
        }
        match exchange.native_record().command.as_str() {
            "GET" => {
                ensure!(
                    exchange.arguments() == [profile.key.clone()],
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
                    for &before in &accesses {
                        super::require_causal_order(before, exchange)?;
                    }
                    ensure!(
                        profile.epochs.len() < 1024,
                        "state observation epoch limit exceeded"
                    );
                    let gate = profile.epochs.last().unwrap().mutation;
                    profile.epochs.push(Epoch {
                        mutation: gate,
                        observations: vec![],
                        // Polling cannot observe completion before required
                        // earlier work on the Source lane has actually run.
                        predecessors: exchanges
                            .iter()
                            .enumerate()
                            .filter(|(_, earlier)| {
                                earlier.source() == DependencyScope::Case
                                    && earlier.case_id() == Some(profile.case.as_str())
                                    && earlier.native_record().connection_id
                                        == exchange.native_record().connection_id
                                    && earlier.native_record().sequence
                                        < exchange.native_record().sequence
                                    && !(earlier.native_record().command == "GET"
                                        && earlier.arguments() == [profile.key.clone()])
                            })
                            .map(|(index, _)| index)
                            .collect(),
                    });
                    accesses.clear();
                }
                value = Some(response);
                accesses.push(exchange);
                observed = true;
                profile.epochs.last_mut().unwrap().observations.push(index);
            }
            "DEL" | "UNLINK" => {
                let removed = super::integer(&response)?;
                let unique = exchange.arguments().iter().collect::<BTreeSet<_>>().len();
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
                if !known_absent {
                    for &before in &accesses {
                        super::require_causal_order(before, exchange)?;
                    }
                }
                super::new_epoch(&mut profile, index)?;
                value = Some(b"$-1\r\n".to_vec());
                if known_absent {
                    // Nil GETs and cleanup that cannot remove this key commute.
                    // The actual DEL remains a finite mutation/epoch gate, but
                    // it does not require ordering within the unchanged state.
                    accesses.push(exchange);
                } else {
                    accesses.clear();
                    mutation = Some(exchange);
                }
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
