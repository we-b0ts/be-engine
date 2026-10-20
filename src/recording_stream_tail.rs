//! Request-side process classification affects waiting, never evidence ownership.

use hyper::{Method, Uri};

use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::config::BackgroundDependencyRuleConfig;
use crate::recorder::api_origin_observation::DependencyRequest;

impl AppState {
    pub(crate) fn capture_http_dependency_request(
        &self,
        method: &Method,
        uri: &Uri,
        authority: Option<&str>,
    ) -> DependencyTargets {
        let process_owned = self
            .config()
            .process_owned_dependencies
            .iter()
            .find(|rule| rule.matches_http_request(method.as_str(), uri, authority));
        let targets = self
            .inner
            .active_cases
            .current_targets_for_http_request(process_owned.is_none());
        match process_owned {
            Some(rule) => targets.into_process_owned(rule.name().to_owned()),
            None => targets,
        }
    }

    pub(crate) fn capture_typed_dependency_request(
        &self,
        request: DependencyRequest<'_>,
    ) -> DependencyTargets {
        let process_owned = self.stream_tail_process_rule(&request);
        let metadata_only = match &request {
            DependencyRequest::Mysql { command, .. } => {
                crate::mysql::wire::is_no_response_command(command)
            }
            DependencyRequest::Redis { command, args, .. } => {
                crate::redis::is_client_library_info(command, args)
            }
        };
        let targets = self
            .inner
            .active_cases
            .current_targets_for_request_with_tail(
                &request,
                process_owned.is_none() && !metadata_only,
            );
        match process_owned {
            Some(rule) => targets.into_process_owned(rule.name().to_owned()),
            None => targets,
        }
    }

    fn stream_tail_process_rule(
        &self,
        request: &DependencyRequest<'_>,
    ) -> Option<&BackgroundDependencyRuleConfig> {
        self.config()
            .process_owned_dependencies
            .iter()
            .find(|rule| {
                if rule.trigger_source().is_some() {
                    return false;
                }
                match (rule, request) {
                    (
                        rule,
                        DependencyRequest::Redis {
                            target_port,
                            command,
                            args,
                        },
                    ) => crate::config::process_owned_dependencies::redis_rule_matches(
                        rule,
                        *target_port,
                        command,
                        args,
                    ),
                    (
                        BackgroundDependencyRuleConfig::Mysql { selector, .. },
                        DependencyRequest::Mysql {
                            target_host,
                            target_port,
                            database,
                            username,
                            command,
                            sql,
                            ..
                        },
                    ) => selector.matches_query(
                        *target_host,
                        *target_port,
                        *database,
                        *username,
                        command,
                        *sql,
                    ),
                    _ => false,
                }
            })
    }
}
