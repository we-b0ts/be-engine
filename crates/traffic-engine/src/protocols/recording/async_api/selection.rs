//! Application selection and cached native event projection for shared async scopes.
use super::*;
use hyper::{Method, Uri};
#[cfg(test)]
use serde_json::Value;

#[cfg(test)]
mod tests;

impl AsyncScope {
    pub fn for_primary(
        rules: &BTreeMap<String, crate::policy::AsyncApiRules>,
        method: &Method,
        uri: &Uri,
        body: &[u8],
    ) -> Option<Self> {
        let body = crate::json_value::parse_with_limit(body, body.len());
        rules.iter().find_map(|(api, rules)| {
            let candidates = rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| {
                    crate::policy::async_api_matches(
                        api,
                        rule,
                        method.as_str(),
                        &uri.to_string(),
                        body.as_ref(),
                    )
                })
                .map(|(index, rule)| {
                    (
                        index,
                        Arc::new(ResourceScope::new(rule.clone())) as Arc<dyn CompletionRule>,
                    )
                })
                .collect::<Vec<_>>();
            AsyncScope::new(api.clone(), candidates)
        })
    }

    #[cfg(test)]
    pub(crate) fn observe_native_at(
        &self,
        event: &RecorderEvent,
        generation: u64,
    ) -> Option<AsyncSignal> {
        self.observe_at(
            &NativeEvent {
                event,
                redis: redis_event::Event::from_event(event),
                actual_sql: OnceCell::new(),
            },
            generation,
        )
    }
    #[cfg(test)]
    pub(crate) fn observe(&self, event: &RecorderEvent) -> Option<AsyncSignal> {
        self.observe_native_at(event, 0)
    }
}

struct NativeEvent<'a> {
    event: &'a RecorderEvent,
    redis: Option<redis_event::Event<'a>>,
    actual_sql: OnceCell<Option<Vec<Token>>>,
}
impl CompletionEvent for NativeEvent<'_> {
    fn identity(&self) -> Option<uuid::Uuid> {
        match self.event {
            RecorderEvent::RedisExchange(event) => Some(event.id),
            RecorderEvent::MysqlExchange(event) => Some(event.id),
            RecorderEvent::HttpExchange(event) => Some(event.id),
            _ => None,
        }
    }
    fn evaluate(&self, rule: &dyn CompletionRule) -> Option<AsyncSignal> {
        rule.as_any()
            .downcast_ref::<ResourceScope>()?
            .observe_cached(self.event, self.redis.as_ref(), &self.actual_sql)
    }
}

impl From<BTreeMap<String, crate::policy::AsyncApiRules>>
    for crate::recorder::async_api::CompletionPolicy
{
    fn from(rules: BTreeMap<String, crate::policy::AsyncApiRules>) -> Self {
        Self::new(rules)
    }
}
impl crate::recorder::async_api::CompletionSource
    for BTreeMap<String, crate::policy::AsyncApiRules>
{
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
    fn select(
        &self,
        request: &serde_json::Value,
        response: &serde_json::Value,
    ) -> anyhow::Result<Option<AsyncScope>> {
        use anyhow::Context;
        let method = request["method"]
            .as_str()
            .context("async Source method unavailable")?
            .parse()?;
        let uri = request["uri"]
            .as_str()
            .context("async Source URI unavailable")?
            .parse()?;
        let body = crate::primary_protocol::assertion::native::source_request_body(request)
            .map(|body| serde_json::to_vec(&body))
            .transpose()?
            .unwrap_or_default();
        let Some(scope) = AsyncScope::for_primary(self, &method, &uri, &body) else {
            return Ok(None);
        };
        let body = crate::primary_protocol::assertion::native::source_request_body(response);
        Ok(scope.select_response(body.as_ref()).0.then_some(scope))
    }
    fn requirements(
        &self,
        captured: Option<&serde_json::Value>,
    ) -> Arc<dyn std::any::Any + Send + Sync> {
        let selected = captured.and_then(|capture| {
            self.get(capture["api"].as_str()?)?
                .get(usize::try_from(capture["scenario_index"].as_u64()?).ok()?)
        });
        let scenarios = selected.map_or_else(
            || {
                self.values()
                    .flat_map(|rules| rules.iter())
                    .collect::<Vec<_>>()
            },
            |selected| vec![selected],
        );
        let ends = scenarios
            .into_iter()
            .flat_map(|rule| &rule.end)
            .filter_map(|end| match end {
                crate::policy::AsyncEnd::Http(end) => Some(end.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        Arc::new(ends)
    }
}

impl crate::active_case::ActiveCaseRegistry {
    pub(crate) fn observe_async_dependency_event(
        &self,
        event: &RecorderEvent,
        targets: &crate::active_case::DependencyTargets,
        recorded_in_case: bool,
    ) {
        self.observe_async_completion(
            &NativeEvent {
                event,
                redis: redis_event::Event::from_event(event),
                actual_sql: OnceCell::new(),
            },
            targets,
            recorded_in_case,
            event.capture_complete(),
            event.kind(),
        );
    }
}
