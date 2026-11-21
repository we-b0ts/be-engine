//! Lazy Redis facts shared by every selector and candidate for one exchange.
use super::{endpoint_matches, response, templates};
use crate::DependencyExchangeOutcome;
use crate::policy::AsyncRedisEnd;
use crate::protocols::recording::events::RecorderEvent;
use crate::recorder::BodyCapture;
use std::cell::OnceCell;

pub(super) struct Exchange<'a> {
    pub(super) command: &'a str,
    pub(super) args: &'a [BodyCapture],
    pub(super) target_host: &'a str,
    pub(super) target_port: u16,
    pub(super) database: i64,
    pub(super) response_kind: &'a str,
    pub(super) resp_version: Option<u8>,
    pub(super) response: Option<&'a BodyCapture>,
    pub(super) outcome: DependencyExchangeOutcome,
    pub(super) parse_warnings: Option<&'a [String]>,
}

pub(super) struct Event<'a> {
    pub(super) exchange: Exchange<'a>,
    arguments: OnceCell<Option<Vec<Vec<u8>>>>,
    keys: OnceCell<Option<Vec<Vec<u8>>>>,
    reply: OnceCell<Option<response::Reply>>,
    message: OnceCell<Option<serde_json::Value>>,
    #[cfg(test)]
    parses: std::cell::Cell<[usize; 4]>,
}

impl<'a> Event<'a> {
    pub(super) fn new(exchange: Exchange<'a>) -> Self {
        Self {
            exchange,
            arguments: OnceCell::new(),
            keys: OnceCell::new(),
            reply: OnceCell::new(),
            message: OnceCell::new(),
            #[cfg(test)]
            parses: Default::default(),
        }
    }

    pub(super) fn from_event(event: &'a RecorderEvent) -> Option<Self> {
        let RecorderEvent::RedisExchange(event) = event else {
            return None;
        };
        Some(Self::new(Exchange {
            command: &event.command,
            args: &event.args,
            target_host: &event.target_host,
            target_port: event.target_port,
            database: event.database,
            response_kind: &event.response_kind,
            resp_version: Some(event.resp_version),
            response: Some(&event.response),
            outcome: event.outcome,
            parse_warnings: Some(&event.parse_warnings),
        }))
    }

    pub(super) fn arguments(&self) -> Option<&[Vec<u8>]> {
        self.arguments
            .get_or_init(|| {
                #[cfg(test)]
                self.note_parse(0);
                self.exchange.args.iter().map(response::complete).collect()
            })
            .as_deref()
    }

    pub(super) fn keys(&self) -> Option<&[Vec<u8>]> {
        self.keys
            .get_or_init(|| {
                #[cfg(test)]
                self.note_parse(1);
                let args = self.arguments()?;
                let positions = crate::redis::key_slots::key_indices(
                    &self.exchange.command.to_ascii_uppercase(),
                    args,
                )
                .ok()?;
                Some(
                    positions
                        .into_iter()
                        .map(|index| args[index].clone())
                        .collect(),
                )
            })
            .as_deref()
    }

    pub(super) fn reply(&self) -> Option<response::Reply> {
        *self.reply.get_or_init(|| {
            #[cfg(test)]
            self.note_parse(2);
            response::parse(response::Exchange {
                body: self.exchange.response?,
                kind: self.exchange.response_kind,
                version: self.exchange.resp_version?,
                outcome: self.exchange.outcome,
                warnings: self.exchange.parse_warnings?,
            })
        })
    }

    pub(super) fn message(&self) -> Option<&serde_json::Value> {
        self.message
            .get_or_init(|| {
                #[cfg(test)]
                self.note_parse(3);
                crate::json_value::parse(self.arguments()?.get(1)?)
            })
            .as_ref()
    }

    pub(super) fn matches_key(
        &self,
        end: &AsyncRedisEnd,
        index: usize,
        templates: &templates::Templates,
    ) -> bool {
        let event = &self.exchange;
        event.command.eq_ignore_ascii_case(&end.operation)
            && event.outcome == DependencyExchangeOutcome::Response
            && !matches!(event.response_kind, "error" | "blob_error")
            && event
                .parse_warnings
                .is_some_and(|warnings| warnings.is_empty())
            && end
                .database
                .is_none_or(|database| event.database == database)
            && endpoint_matches(
                &end.endpoint,
                Some(event.target_host),
                Some(event.target_port),
            )
            && self
                .keys()
                .is_some_and(|keys| keys.iter().any(|key| templates.key_matches(index, key)))
            && self
                .reply()
                .is_some_and(|reply| response::matches(reply, end.when_response))
    }

    #[cfg(test)]
    fn note_parse(&self, index: usize) {
        let mut counts = self.parses.get();
        counts[index] += 1;
        self.parses.set(counts);
    }
}

#[cfg(test)]
mod tests;
