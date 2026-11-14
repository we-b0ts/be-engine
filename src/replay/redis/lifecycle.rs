//! Admit only exact Source-stop request refs and retain their physical sockets.
use super::*;
use crate::replay::control::dependency_tail::RecordedReference;

impl RecordedExchange {
    pub(crate) fn cleanup_reference(&self) -> RecordedReference {
        RecordedReference::Redis {
            connection_id: self.native.connection_id,
            sequence: self.native.sequence,
        }
    }

    pub(crate) fn authorize_lifecycle_cleanup(&mut self) -> Result<()> {
        ensure!(
            (self.native.outcome == DependencyExchangeOutcome::Response
                && !self.native.replay_safe
                && self.native.response_kind == "other"
                && self.native.parse_warnings.as_slice()
                    == ["engine cleanup interrupted Redis capture"]
                || self
                    .native
                    .outcome
                    .termination()
                    .is_some_and(|end| end.side != crate::dependency::TerminationSide::Engine
                        && end.scope != crate::dependency::TerminationScope::Stream)
                    && (self.native.parse_warnings.is_empty()
                        || self.native.parse_warnings.as_slice()
                            == ["engine cleanup interrupted Redis capture"]))
                && !self.native.args.iter().any(|capture| capture.truncated)
                && !self.native.response.truncated,
            "Redis lifecycle cleanup requires an exact admitted complete request and no independent capture corruption"
        );
        for argument in &self.native.args {
            argument.decode()?;
        }
        self.native.response.decode()?;
        self.lifecycle_cleanup = true;
        Ok(())
    }
}

pub(super) async fn deliver(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    matched: &MatchedRedisExchange,
    client_id: Uuid,
) -> Result<()> {
    let (case, gate) = {
        let state = state.lock().await;
        let exchange = &state.protocols.redis.exchanges[matched.index];
        let case = exchange
            .case_id
            .clone()
            .context("Redis cleanup has no Case owner")?;
        let gate = state
            .async_cleanup_gate(&case, exchange.record.cleanup_reference())
            .context("Redis request has no authenticated async cleanup context")?;
        (case, gate)
    };
    let additional = claim_pipeline(reader, state, matched, client_id, &case).await?;
    reader.inner.write_all(&matched.response).await?;
    for exchange in &additional {
        reader.inner.write_all(&exchange.response).await?;
    }
    reader.inner.flush().await?;
    {
        let mut state = state.lock().await;
        state.protocols.redis.exchanges[matched.index].status =
            ReplayExchangeStatus::AwaitingClientTermination;
        for exchange in &additional {
            state.protocols.redis.exchanges[exchange.index].status =
                ReplayExchangeStatus::AwaitingClientTermination;
        }
    }
    let result =
        super::super::lifecycle_cleanup::await_target_end(&mut reader.inner, &gate, state, &case)
            .await;
    let mut state = state.lock().await;
    for exchange in &additional {
        if let Err(error) = &result {
            state
                .protocols
                .redis
                .fail_exchange(exchange, error.to_string());
        } else {
            state.protocols.redis.complete_exchange(exchange);
        }
    }
    result
}

async fn claim_pipeline(
    reader: &mut RedisBufferedReader<&mut TcpStream>,
    state: &Arc<Mutex<ReplayState>>,
    first: &MatchedRedisExchange,
    client_id: Uuid,
    case: &str,
) -> Result<Vec<MatchedRedisExchange>> {
    let mut pipeline = Vec::new();
    loop {
        let pending = state
            .lock()
            .await
            .protocols
            .redis
            .exchanges
            .iter()
            .any(|exchange| {
                exchange.case_id.as_deref() == Some(case)
                    && exchange.source == ReplaySource::Case
                    && exchange.record.native.connection_id == first.connection_id
                    && exchange.record.lifecycle_cleanup
                    && exchange.status.is_available()
            });
        if !pending {
            break;
        }
        let frame = read_redis_frame(reader)
            .await?
            .context("Target closed before its admitted Redis pipeline was complete")?;
        let command = redis_command(&frame.raw)?;
        let mut state = state.lock().await;
        let record = state.protocols.redis.exchanges[first.index].record.clone();
        let connection = TargetConnection {
            id: client_id,
            bound: Some(first.connection_id),
        };
        let matched = if redis_is_builtin(&command.name) {
            state
                .protocols
                .redis
                .match_redis_builtin_failure(
                    Some(case),
                    &first.report.target,
                    connection,
                    record.native.resp_version,
                    record.native.database,
                    record.native.username.as_deref(),
                    &command,
                )
                .context("no admitted Redis cleanup request matched the pipeline")?
        } else {
            state
                .protocols
                .redis
                .match_redis(
                    Some(case),
                    &first.report.target,
                    connection,
                    record.native.resp_version,
                    record.native.database,
                    record.native.username.as_deref(),
                    &command.name,
                    &command.args,
                )
                .map_err(|_| anyhow!("no admitted Redis cleanup request matched the pipeline"))?
        };
        ensure!(
            matched.connection_id == first.connection_id
                && state.protocols.redis.exchanges[matched.index]
                    .record
                    .lifecycle_cleanup,
            "Redis cleanup pipeline cannot claim an ordinary response"
        );
        pipeline.push(matched);
    }
    ensure!(
        reader.buffer.is_empty(),
        "Target sent extra commands beyond its admitted Redis cleanup pipeline"
    );
    Ok(pipeline)
}
