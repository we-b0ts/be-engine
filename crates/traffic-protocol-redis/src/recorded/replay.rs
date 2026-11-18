//! Native stored RESP completeness and replay decoding.
use super::RecordedExchange;
use anyhow::{Result, anyhow, ensure};
use traffic_model::DependencyExchangeOutcome;

pub struct DecodedExchange {
    pub args: Vec<Vec<u8>>,
    pub response: Vec<u8>,
}

impl RecordedExchange {
    pub fn decode_replay(&self, cleanup_authorized: bool) -> Result<DecodedExchange> {
        self.outcome.validate()?;
        ensure!(
            self.outcome
                .termination()
                .is_none_or(|end| end.scope != traffic_model::TerminationScope::Stream),
            "Redis termination must describe a TCP connection direction"
        );
        ensure!(
            (self.replay_safe || cleanup_authorized)
                && !self.response.truncated
                && !self.args.iter().any(|capture| capture.truncated),
            "redis_exchange command {} contains unsafe or truncated replay evidence",
            self.command
        );
        let args = self
            .args
            .iter()
            .map(super::RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        let response = self.response.decode()?;
        ensure!(
            self.outcome
                .termination()
                .is_none_or(|end| end.side != traffic_model::TerminationSide::Client)
                || response.is_empty(),
            "Redis client termination response prefix has no recorded delivery timing"
        );
        if !cleanup_authorized {
            self.validate_subscription(&args, &response)?;
        }
        Ok(DecodedExchange { args, response })
    }

    pub fn validate_cleanup(&self) -> Result<()> {
        ensure!(
            (self.outcome == DependencyExchangeOutcome::Response
                && !self.replay_safe
                && self.response_kind == "other"
                && self.parse_warnings.as_slice() == ["engine cleanup interrupted Redis capture"]
                || self
                    .outcome
                    .termination()
                    .is_some_and(|end| end.side != traffic_model::TerminationSide::Engine
                        && end.scope != traffic_model::TerminationScope::Stream)
                    && (self.parse_warnings.is_empty()
                        || self.parse_warnings.as_slice()
                            == ["engine cleanup interrupted Redis capture"]))
                && !self.args.iter().any(|capture| capture.truncated)
                && !self.response.truncated,
            "Redis lifecycle cleanup requires an exact admitted complete request and no independent capture corruption"
        );
        for argument in &self.args {
            argument.decode()?;
        }
        self.response.decode()?;
        Ok(())
    }
    pub fn validate_subscription(&self, args: &[Vec<u8>], response: &[u8]) -> Result<()> {
        if !crate::is_pubsub_command(&self.command) || self.outcome.termination().is_some() {
            return Ok(());
        }

        ensure!(
            self.resp_version == 2,
            "Redis Pub/Sub replay requires RESP2"
        );
        ensure!(
            args.len() == 1,
            "Redis {} confirmation replay requires exactly one subscription argument",
            self.command
        );

        let command = crate::RedisCommand {
            name: self.command.clone(),
            args: args.to_vec(),
        };
        match self.response_kind.as_str() {
            "array" => crate::validate_subscription_confirmation(&command, response),
            "error" => {
                let raw = bytes::Bytes::copy_from_slice(response);
                ensure!(
                    crate::frame_kind(&raw)? == crate::RedisFrameKind::Error,
                    "Redis {} recorded error response is not a RESP2 error frame",
                    self.command
                );
                Ok(())
            }
            other => Err(anyhow!(
                "Redis {} replay requires an exact subscription confirmation or error, got {other}",
                self.command
            )),
        }
    }
}
