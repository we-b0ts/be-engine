//! Successful finite Redis publication selected by its channel and JSON message.
use super::{endpoint_matches, redis_event, response};
use crate::DependencyExchangeOutcome;
use crate::policy::AsyncRedisPublishEnd;
pub(super) fn matches(end: &AsyncRedisPublishEnd, cached: &redis_event::Event<'_>) -> bool {
    let event = &cached.exchange;
    if !end.operation.eq_ignore_ascii_case("PUBLISH")
        || !event.command.eq_ignore_ascii_case("PUBLISH")
        || event.outcome != DependencyExchangeOutcome::Response
        || event.response_kind != "integer"
        || event
            .parse_warnings
            .is_none_or(|warnings| !warnings.is_empty())
        || end.when_message.is_empty()
        || end.database.is_some_and(|db| event.database != db)
        || !endpoint_matches(
            &end.endpoint,
            Some(event.target_host),
            Some(event.target_port),
        )
    {
        return false;
    }
    let Some([channel, _]) = cached.arguments() else {
        return false;
    };
    if channel != end.channel.as_bytes() {
        return false;
    }
    let Some(reply) = cached.reply() else {
        return false;
    };
    if !matches!(reply, response::Reply::Integer(subscribers) if subscribers >= 0)
        || !response::matches(reply, end.when_response)
    {
        return false;
    }
    let Some(message) = cached.message() else {
        return false;
    };
    end.when_message
        .iter()
        .all(|(pointer, expected)| message.pointer(pointer) == Some(expected))
}

#[cfg(test)]
mod tests;
