//! Preserve the exact Source commands that make request contracts applicable.
use super::*;
use crate::replay::policy::{pattern, redis_value::RedisSelector, report::RecordedRedisRuleSource};

#[derive(Default)]
pub(super) struct RedisApplicability {
    sources: BTreeMap<String, BTreeSet<RecordedRedisRuleSource>>,
    incomplete: BTreeSet<String>,
}

impl RequestContracts {
    pub(in crate::replay) fn observe_source(&self, case: &str, bytes: &[u8]) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        self.register_source_records(case, bytes)?;
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let event: Value = serde_json::from_slice(line)?;
            if !crate::dependency::observation::is_case_event(&event) {
                continue;
            }
            self.observe_unified_source(case, &event)?;
            let protocol = match event["event_type"].as_str() {
                Some("redis_exchange") => DependencyProtocol::Redis,
                Some("http_exchange") => DependencyProtocol::Http,
                _ => continue,
            };
            let target = if protocol == DependencyProtocol::Redis {
                TargetKey {
                    host: event["target_host"].as_str().unwrap_or_default().into(),
                    port: event["target_port"].as_u64().unwrap_or_default() as u16,
                }
            } else {
                let Ok(authority) = event["authority"]
                    .as_str()
                    .unwrap_or_default()
                    .parse::<hyper::http::uri::Authority>()
                else {
                    continue;
                };
                TargetKey {
                    host: authority.host().into(),
                    port: authority.port_u16().unwrap_or(
                        if event["scheme"]
                            .as_str()
                            .is_some_and(|s| s.contains("https"))
                        {
                            443
                        } else {
                            80
                        },
                    ),
                }
            };
            for rule in self.selected(case, &target, protocol) {
                let native_protocol = if protocol == DependencyProtocol::Redis {
                    crate::policy::Protocol::Redis
                } else {
                    crate::policy::Protocol::Http
                };
                let database = event["database"]
                    .as_i64()
                    .map(crate::policy::Database::Index);
                if !self.native_rule_scope_matches(
                    &rule.id,
                    Some(case),
                    native_protocol,
                    &target,
                    database.as_ref(),
                    event["username"].as_str(),
                ) {
                    continue;
                }
                let matches = if let Some(RedisSelector::Requests(selector)) = &rule.redis {
                    selector
                        .database
                        .is_none_or(|database| event["database"].as_i64() == Some(database))
                        && selector
                            .commands
                            .iter()
                            .filter(|c| event["command"] == c.command)
                            .any(|command| {
                                event["args"]
                                    .as_array()
                                    .and_then(|args| {
                                        args.iter()
                                            .map(evidence::decode)
                                            .collect::<Result<Vec<_>>>()
                                            .ok()
                                    })
                                    .is_some_and(|args| {
                                        command.validate_arguments(&args).is_ok()
                                            && command
                                                .key(&args)
                                                .is_some_and(|key| selector.key.matches(key))
                                    })
                            })
                } else {
                    rule.http.as_ref().is_some_and(|h| {
                        event["method"] == h.method
                            && pattern::path_pattern_matches(
                                &h.path,
                                &pattern::uri_path(event["uri"].as_str().unwrap_or_default()),
                            )
                    })
                };
                if matches {
                    self.observe_source_applicability(case, &event, [rule.id.clone()]);
                }
            }
        }
        Ok(())
    }

    pub(super) fn observe_source_applicability(
        &self,
        case: &str,
        event: &Value,
        ids: impl IntoIterator<Item = String>,
    ) {
        let mut state = self.state.lock().expect("request contracts");
        for id in ids {
            state.applicable.insert(id.clone());
            if event["event_type"] != "redis_exchange" {
                continue;
            }
            let source = event["connection_id"]
                .as_str()
                .filter(|connection| !connection.is_empty() && !case.is_empty())
                .zip(event["sequence"].as_u64().filter(|sequence| *sequence > 0))
                .map(|(connection, sequence)| RecordedRedisRuleSource {
                    case_id: case.into(),
                    connection_id: connection.into(),
                    sequence,
                });
            if let Some(source) = source {
                state
                    .redis_applicability
                    .sources
                    .entry(id)
                    .or_default()
                    .insert(source);
            } else {
                // A partial inventory must never remove an obligation, even if
                // every other matching Source command was moved to background.
                state.redis_applicability.incomplete.insert(id);
            }
        }
    }

    pub(in crate::replay) fn recorded_redis_rule_applicability(
        &self,
    ) -> BTreeMap<String, BTreeSet<RecordedRedisRuleSource>> {
        let state = self.state.lock().expect("request contracts");
        state
            .redis_applicability
            .sources
            .iter()
            .filter(|(id, _)| !state.redis_applicability.incomplete.contains(*id))
            .map(|(id, sources)| (id.clone(), sources.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_source_identity_invalidates_the_entire_redis_rule_inventory() {
        for missing in ["connection_id", "sequence"] {
            let runtime = RequestContracts::default();
            let event = json!({"event_type":"redis_exchange","connection_id":"lane","sequence":2});
            runtime.observe_source_applicability("case", &event, ["rule".into()]);
            assert!(
                runtime
                    .recorded_redis_rule_applicability()
                    .contains_key("rule")
            );
            let mut incomplete = event.clone();
            incomplete.as_object_mut().unwrap().remove(missing);
            runtime.observe_source_applicability("case", &incomplete, ["rule".into()]);
            runtime.observe_source_applicability("case", &event, ["rule".into()]);
            assert!(runtime.recorded_redis_rule_applicability().is_empty());
            assert!(runtime.state.lock().unwrap().applicable.contains("rule"));
        }
    }
}
