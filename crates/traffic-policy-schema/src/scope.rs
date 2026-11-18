//! Eligibility is chosen from immutable Source identity, before normalization.
use crate::{Database, Protocol, Resource, SourceCondition};
use traffic_protocol::connection::Endpoint as TargetKey;

/// A scope stays attached to its native identity until the domain owner installs it.
/// Returning a document alone would silently discard method/database/auth guards.
#[derive(Debug, Clone)]
pub struct NativeScopeGuard {
    pub id: String,
    pub selector: crate::native::NativeMatch,
    pub when: Option<SourceCondition>,
    pub references: Vec<Resource>,
}

impl NativeScopeGuard {
    pub fn from_rule(rule: &crate::native::NativeRule) -> Self {
        Self {
            id: rule.id.clone(),
            selector: rule.selector.clone(),
            when: rule.when.clone(),
            references: match &rule.effect {
                crate::native::NativeEffect::Identity(effect) => effect
                    .references
                    .iter()
                    .map(|reference| reference.contract.resource.clone())
                    .collect(),
                _ => vec![],
            },
        }
    }
}

impl NativeScopeGuard {
    pub fn matches_case(
        &self,
        method: &str,
        path: &str,
        source_body: Option<&serde_json::Value>,
    ) -> bool {
        self.selector.api.as_deref().is_none_or(|api| {
            api.split_once(' ')
                .is_some_and(|(expected_method, expected_path)| {
                    expected_method == method
                        && traffic_protocol_http::path_pattern::matches_path_pattern(
                            expected_path,
                            path,
                        )
                })
        }) && self
            .when
            .as_ref()
            .is_none_or(|condition| source_body.is_some_and(|body| condition.matches_body(body)))
    }

    pub fn matches_capture_resource(
        &self,
        protocol: Protocol,
        target: &TargetKey,
        database: Option<&Database>,
        username: Option<&str>,
    ) -> bool {
        if let Some(host) = &self.selector.http_host
            && (protocol != Protocol::Http
                || traffic_protocol::observation::normalize_host(host)
                    != traffic_protocol::observation::normalize_host(&target.host))
        {
            return false;
        }
        self.selector.resource.as_ref().map_or_else(
            || self.selector.http_host.is_some() && protocol == Protocol::Http,
            |resource| matches_resource(resource, protocol, target, database, username),
        )
    }

    pub fn matches_reference_resource(
        &self,
        protocol: Protocol,
        target: &TargetKey,
        database: Option<&Database>,
        username: Option<&str>,
    ) -> bool {
        self.references
            .iter()
            .any(|resource| matches_resource(resource, protocol, target, database, username))
    }
}

fn matches_resource(
    resource: &Resource,
    protocol: Protocol,
    target: &TargetKey,
    database: Option<&Database>,
    username: Option<&str>,
) -> bool {
    resource.protocol == protocol
        && traffic_protocol::observation::normalize_host(&resource.endpoint.host)
            == traffic_protocol::observation::normalize_host(&target.host)
        && resource.endpoint.port == target.port
        && resource
            .database
            .as_ref()
            .is_none_or(|expected| Some(expected) == database)
        && resource
            .username
            .as_deref()
            .is_none_or(|expected| Some(expected) == username)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::NativeMatch;
    use crate::{Endpoint, EqualsPredicate, SourceCondition, SourcePredicate, SourceScalar};
    use std::collections::BTreeMap;

    #[test]
    fn host_only_http_scope_filters_host_and_keeps_ports_discovered() {
        let guard = NativeScopeGuard {
            id: "cache".into(),
            selector: NativeMatch {
                http_host: Some("Metadata.Example.Test".into()),
                ..Default::default()
            },
            when: None,
            references: vec![],
        };
        for port in [80, 443, 8080] {
            let target = TargetKey {
                host: "metadata.example.test.".into(),
                port,
            };
            assert!(guard.matches_capture_resource(Protocol::Http, &target, None, None));
            assert!(!guard.matches_capture_resource(Protocol::Redis, &target, None, None));
        }
        assert!(!guard.matches_capture_resource(
            Protocol::Http,
            &TargetKey {
                host: "other.example.test".into(),
                port: 443
            },
            None,
            None
        ));
    }

    #[test]
    fn native_scopes_keep_method_source_condition_database_and_auth_independent() {
        let resource = Resource {
            protocol: Protocol::Redis,
            endpoint: Endpoint {
                host: "cache.example".into(),
                port: 6379,
            },
            database: Some(Database::Index(1)),
            username: Some("writer".into()),
        };
        let guard = NativeScopeGuard {
            id: "identity".into(),
            selector: NativeMatch {
                api: Some("POST /tasks/*".into()),
                resource: Some(resource.clone()),
                ..Default::default()
            },
            when: Some(SourceCondition {
                request_body_json: BTreeMap::from([(
                    "/background".into(),
                    SourcePredicate::Equals(EqualsPredicate {
                        equals: SourceScalar::Bool(true),
                    }),
                )]),
            }),
            references: vec![resource],
        };
        assert!(guard.matches_case(
            "POST",
            "/tasks/1",
            Some(&serde_json::json!({"background":true}))
        ));
        assert!(!guard.matches_case(
            "GET",
            "/tasks/1",
            Some(&serde_json::json!({"background":true}))
        ));
        assert!(!guard.matches_case(
            "POST",
            "/tasks/1",
            Some(&serde_json::json!({"background":false}))
        ));
        assert!(!guard.matches_case("POST", "/tasks/1", None));
        let target = TargetKey {
            host: "CACHE.EXAMPLE".into(),
            port: 6379,
        };
        assert!(guard.matches_capture_resource(
            Protocol::Redis,
            &target,
            Some(&Database::Index(1)),
            Some("writer")
        ));
        assert!(!guard.matches_capture_resource(
            Protocol::Redis,
            &target,
            Some(&Database::Index(2)),
            Some("writer")
        ));
        assert!(!guard.matches_capture_resource(
            Protocol::Redis,
            &target,
            Some(&Database::Index(1)),
            Some("reader")
        ));
        assert!(!guard.matches_reference_resource(Protocol::Memcached, &target, None, None));
    }
}
