//! Native identity copies retain Source case and protocol identity at every use.
use super::*;
use crate::policy::{CompiledNativeRule, Database, Protocol};

#[derive(Clone, Copy)]
pub(super) struct ResourceContext<'a> {
    pub protocol: Protocol,
    pub target: &'a TargetKey,
    pub database: Option<&'a Database>,
    pub username: Option<&'a str>,
    pub operation: &'a str,
}

impl DynamicValues {
    pub(crate) fn configure_native(&mut self, rules: &[CompiledNativeRule]) {
        self.native_guards = Arc::new(
            rules
                .iter()
                .filter(|rule| matches!(rule.rule.effect, crate::policy::NativeEffect::Identity(_)))
                .map(|rule| {
                    (
                        rule.rule.id.clone(),
                        super::super::native_projection::NativeScopeGuard::from_rule(&rule.rule),
                    )
                })
                .collect(),
        );
    }

    pub(super) fn set_native_request(&mut self, case: &str, request: &serde_json::Value) {
        let method = request["method"].as_str().unwrap_or_default();
        let path = super::super::pattern::uri_path(request["uri"].as_str().unwrap_or_default());
        let body = super::super::case_condition::request_body(request);
        let ids = self
            .native_guards
            .values()
            .filter(|guard| guard.matches_case(method, &path, body.as_ref()))
            .map(|guard| guard.id.clone())
            .collect();
        Arc::make_mut(&mut self.native_cases).insert(case.into(), ids);
    }

    pub(super) fn selected_scoped(
        &self,
        case: &str,
        context: ResourceContext<'_>,
        capture: bool,
    ) -> Vec<&DynamicValueRule> {
        self.rules
            .iter()
            .filter(|rule| {
                self.matches_case(rule, case)
                    && if let Some(guard) = self.native_guards.get(&rule.id) {
                        if capture {
                            guard.selector.operation.as_deref().is_none_or(|operation| {
                                operation.eq_ignore_ascii_case(context.operation)
                            }) && guard.matches_capture_resource(
                                context.protocol,
                                context.target,
                                context.database,
                                context.username,
                            )
                        } else {
                            guard.matches_reference_resource(
                                context.protocol,
                                context.target,
                                context.database,
                                context.username,
                            )
                        }
                    } else {
                        rule.targets
                            .iter()
                            .any(|target| target.matches(context.target))
                    }
            })
            .collect()
    }

    pub(super) fn scoped_pairs(
        &self,
        case: &str,
        context: ResourceContext<'_>,
        pending: &DynamicDecision,
    ) -> Vec<IdentityPair> {
        let bindings = self.bindings.lock().expect("dynamic bindings");
        self.selected_scoped(case, context, false)
            .into_iter()
            .filter(|rule| rule.value_type == DynamicValueType::String)
            .flat_map(|rule| {
                bindings
                    .get(case)
                    .and_then(|rules| rules.get(&rule.id))
                    .into_iter()
                    .flatten()
                    .cloned()
                    .chain(
                        pending
                            .pairs
                            .iter()
                            .filter(|(id, _)| id == &rule.id)
                            .map(|(_, pair)| pair.clone()),
                    )
            })
            .collect()
    }

    pub(super) fn native_source_allowed(
        &self,
        rule: &DynamicValueRule,
        event: &serde_json::Value,
    ) -> bool {
        let Some(guard) = self.native_guards.get(&rule.id) else {
            return true;
        };
        let protocol = match event["event_type"].as_str() {
            Some("mysql_exchange") => Protocol::Mysql,
            Some("redis_exchange") => Protocol::Redis,
            Some("http_exchange") => Protocol::Http,
            _ => return false,
        };
        let uri = event["uri"]
            .as_str()
            .and_then(|raw| raw.parse::<hyper::Uri>().ok());
        let authority = event["authority"]
            .as_str()
            .and_then(|raw| raw.parse::<hyper::http::uri::Authority>().ok())
            .or_else(|| uri.as_ref().and_then(|uri| uri.authority().cloned()));
        let host = event["target_host"]
            .as_str()
            .or_else(|| authority.as_ref().map(|value| value.host()));
        let port = event["target_port"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or_else(|| {
                authority.as_ref().map(|value| {
                    value.port_u16().unwrap_or(
                        if matches!(
                            event["scheme"].as_str(),
                            Some("https" | "intercepted_https" | "fake_ip_https")
                        ) {
                            443
                        } else {
                            80
                        },
                    )
                })
            });
        let (Some(host), Some(port)) = (host, port) else {
            return false;
        };
        let database = match protocol {
            Protocol::Mysql => event["database"]
                .as_str()
                .map(|value| Database::Name(value.into())),
            Protocol::Redis => event["database"].as_i64().map(Database::Index),
            _ => None,
        };
        guard.selector.operation.as_deref().is_none_or(|operation| {
            event["command"]
                .as_str()
                .or_else(|| event["method"].as_str())
                .is_some_and(|actual| operation.eq_ignore_ascii_case(actual))
        }) && guard.matches_capture_resource(
            protocol,
            &TargetKey {
                host: host.into(),
                port,
            },
            database.as_ref(),
            event["username"].as_str(),
        )
    }
}
