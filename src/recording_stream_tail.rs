//! Request-start selectors freeze whole-task capture ownership before forwarding.

use hyper::{Method, Uri};

use crate::AppState;
use crate::active_case::DependencyTargets;
use crate::config::BackgroundDependencyRuleConfig;
use crate::protocols::recording::request::DependencyRequest;

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
            .filter(|rule| rule.matches_http_request(method.as_str(), uri, authority))
            .map(|rule| rule.name().to_owned())
            .collect::<Vec<_>>();
        let definite = crate::recorder::process_classification::definite_process(
            &process_owned,
            &self.config().process_dependency_tasks,
        );
        let targets = self
            .inner
            .active_cases
            .current_targets_for_http_request(!definite);
        crate::recorder::process_classification::classify(
            targets,
            process_owned,
            &self.config().process_dependency_tasks,
        )
    }

    pub(crate) fn capture_typed_dependency_request(
        &self,
        request: DependencyRequest<'_>,
    ) -> DependencyTargets {
        let process_owned = self.stream_tail_process_rules(&request);
        let metadata_only = match &request {
            DependencyRequest::Mysql { command, .. } => {
                crate::mysql::wire::is_no_response_command(command)
            }
            DependencyRequest::Redis { command, args, .. } => {
                crate::redis::is_client_library_info(command, args)
            }
        };
        let targets = self.process_observation_targets(&process_owned, !metadata_only);
        crate::recorder::process_classification::classify(
            targets,
            process_owned,
            &self.config().process_dependency_tasks,
        )
    }

    fn process_observation_targets(&self, rules: &[String], business: bool) -> DependencyTargets {
        let definite = crate::recorder::process_classification::definite_process(
            rules,
            &self.config().process_dependency_tasks,
        );
        self.inner
            .active_cases
            .current_targets_for_request_with_tail(business && !definite)
    }

    fn stream_tail_process_rules(&self, request: &DependencyRequest<'_>) -> Vec<String> {
        self.config()
            .process_owned_dependencies
            .iter()
            .filter(|rule| {
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
            .map(|rule| rule.name().to_owned())
            .collect()
    }
}
