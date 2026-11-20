//! Acquisition and ownership consume typed policy effects, without another file format.
use anyhow::{Context, Result, ensure};

use crate::policy::native as n;
use crate::policy::{CompiledNativeRule, Database};
mod reverse;
mod update;
pub use update::{empty_policy, render_updated};

pub fn parse_source_policy(raw: &str) -> Result<SourceTrafficPolicyConfig> {
    Ok(parse_source_with_fingerprints(raw)?.0)
}

pub fn parse_source_with_fingerprints(
    raw: &str,
) -> Result<(SourceTrafficPolicyConfig, crate::policy::PolicyFingerprints)> {
    let compiled = crate::policy::parse_and_compile_policy(raw)?;
    let mut projected = project_source_policy(&compiled.native)?;
    projected.async_api = compiled.async_api.clone();
    Ok((projected, compiled.fingerprints))
}

#[cfg(any(test, feature = "test-support"))]
pub fn render_initial(config: &SourceTrafficPolicyConfig) -> Result<String> {
    let proof = crate::policy::Proof {
        source: "traffic-e2e Source owner bootstrap".into(),
        fact: "Explicit Source acquisition and ownership settings define these effects".into(),
    };
    let rules = reverse::rules(config, &proof)?;
    let document = crate::policy::TrafficPolicy {
        format: crate::policy::POLICY_FORMAT.into(),
        source_revision: None,
        async_api: (!config.async_api.is_empty()).then(|| config.async_api.clone()),
        rules: rules.into_iter().map(Into::into).collect(),
        ..Default::default()
    };
    crate::policy::compile_policy(&document)?;
    crate::policy::render_policy(&document)
}

use super::process_owned_dependencies::{
    BackgroundDependencyRuleConfig as B, RedisKeyPatternConfig,
};
use super::source_traffic_policy::{
    SOURCE_TRAFFIC_POLICY_VERSION, SourceTrafficHttpPolicyConfig, SourceTrafficPolicyConfig,
};

pub fn project_source_policy(rules: &[CompiledNativeRule]) -> Result<SourceTrafficPolicyConfig> {
    let mut output = SourceTrafficPolicyConfig {
        version: SOURCE_TRAFFIC_POLICY_VERSION,
        http: SourceTrafficHttpPolicyConfig::default(),
        http_response_rewrite: vec![],
        process_owned_dependencies: vec![],
        process_dependency_tasks: Default::default(),
        async_api: Default::default(),
    };
    for compiled in rules {
        let rule = &compiled.rule;
        match &rule.effect {
            n::NativeEffect::CaptureHttp(effect) => {
                ensure!(
                    output.http.source_revision.is_empty()
                        || output.http.source_revision == effect.source_revision,
                    "capture scope revisions must describe the same Source snapshot"
                );
                output.http.source_revision = effect.source_revision.clone();
                output
                    .http
                    .case_path_patterns
                    .extend(effect.case_paths.iter().cloned());
            }
            n::NativeEffect::CaptureHttpResponse(effect) => output
                .http_response_rewrite
                .push(capture_response(rule, effect)),
            n::NativeEffect::ProcessOwned(effect) => {
                output
                    .process_owned_dependencies
                    .push(process_owned(rule, effect)?);
                if effect.origin.is_none()
                    && let Some(task) = &effect.task_name
                {
                    output
                        .process_dependency_tasks
                        .insert(rule.id.clone(), task.clone());
                }
            }
            _ => (),
        }
    }
    output.http.case_path_patterns.sort();
    output.http.case_path_patterns.dedup();
    output.validate()?;
    Ok(output)
}

pub fn capture_response(
    rule: &n::NativeRule,
    effect: &n::CaptureResponseEffect,
) -> super::HttpResponseRewriteRuleConfig {
    let (path, path_pattern) = match &effect.path {
        n::CapturePath::Exact { value } => (value.clone(), None),
        n::CapturePath::Pattern { value } => (String::new(), Some(value.clone())),
    };
    let (pointers, plugin) = match &effect.contract {
        n::CaptureResponseContract::Policy(definition) => (
            vec![],
            Some(super::HttpResponseRewritePluginConfig::Policy(
                definition.clone(),
            )),
        ),
        n::CaptureResponseContract::Urls { pointers } => (
            pointers
                .iter()
                .map(|pointer| pointer.contract.clone())
                .collect(),
            None,
        ),
        n::CaptureResponseContract::Kubeconfig {
            kubectl_binary,
            proxy_listen,
        } => (
            vec![],
            Some(super::HttpResponseRewritePluginConfig::PlutoEciKubeconfig {
                kubectl_binary: kubectl_binary.clone(),
                proxy_listen: *proxy_listen,
            }),
        ),
        n::CaptureResponseContract::Documents { rules } => (
            vec![],
            Some(super::HttpResponseRewritePluginConfig::Documents {
                rules: rules.clone(),
            }),
        ),
    };
    super::HttpResponseRewriteRuleConfig {
        name: rule.id.clone(),
        authorities: effect.authorities.clone(),
        methods: effect.methods.clone(),
        path,
        path_pattern,
        pointers,
        status_codes: effect.status_codes.clone(),
        content_types: effect.content_types.clone(),
        plugin,
        source_evidence: proof(rule.proof.as_ref()),
    }
}

fn process_owned(rule: &n::NativeRule, effect: &n::ProcessOwnedEffect) -> Result<B> {
    let name = rule.id.clone();
    let source_revision = effect.source_revision.clone();
    let source_evidence = proof(rule.proof.as_ref());
    let trigger_source = effect
        .origin
        .as_ref()
        .map(|origin| origin_source(&origin.contract))
        .transpose()?;
    Ok(match &effect.selector {
        n::ProcessSelector::RedisScript(selector) => {
            ensure!(
                effect.origin.is_none(),
                "finite Redis script ownership cannot have an API origin"
            );
            B::RedisScript {
                name,
                source_revision,
                source_evidence,
                selector: selector.clone(),
            }
        }
        n::ProcessSelector::RedisPubsub(selector) => B::RedisPubsub {
            name,
            source_revision,
            source_evidence,
            selector: selector.clone(),
        },
        n::ProcessSelector::Mysql {
            selector,
            include_transaction_boundaries,
            transaction_members,
            identity_value_index,
        } => B::Mysql {
            name,
            source_revision,
            source_evidence,
            selector: mysql(selector)?,
            include_transaction_boundaries: *include_transaction_boundaries,
            transaction_members: transaction_members
                .iter()
                .map(|member| mysql(&member.contract))
                .collect::<Result<_>>()?,
            trigger_source,
            identity_value_index: *identity_value_index,
        },
        n::ProcessSelector::Http {
            authorities,
            methods,
            path_prefixes,
        } => B::Http {
            name,
            source_revision,
            source_evidence,
            authorities: authorities.clone(),
            methods: methods.clone(),
            path_prefixes: path_prefixes.clone(),
        },
        n::ProcessSelector::Memcached {
            breeze_identity,
            operation,
            key_start,
            key_end,
            key_separator,
            key_suffix,
            initial_load_timeout_ms,
        } => B::Memcached {
            name,
            source_revision,
            source_evidence,
            breeze_identity: breeze_identity.clone(),
            command: operation.clone(),
            key_start: *key_start,
            key_end: *key_end,
            key_separator: key_separator.clone(),
            key_suffix: key_suffix.clone(),
            initial_load_timeout_ms: *initial_load_timeout_ms,
        },
        n::ProcessSelector::Redis {
            ports,
            operation,
            keys,
            key_templates,
            key_sequence,
            arguments,
            script,
            initial_load_timeout_ms,
            fields,
            when_message,
        } => {
            if operation.eq_ignore_ascii_case("PUBLISH") {
                ensure!(
                    effect.origin.is_none()
                        && key_templates.is_empty()
                        && key_sequence.is_empty()
                        && arguments.is_empty()
                        && script.is_none()
                        && fields.is_empty()
                        && initial_load_timeout_ms.is_none(),
                    "process Redis PUBLISH requires exact channels and finite exchanges"
                );
                let channels = keys
                    .iter()
                    .map(|key| match key {
                        n::NativeKeySelector::Exact { value } => Ok(value.clone()),
                        _ => anyhow::bail!("process Redis PUBLISH requires exact channels"),
                    })
                    .collect::<Result<Vec<_>>>()?;
                return Ok(B::RedisPublish {
                    name,
                    source_revision,
                    source_evidence,
                    selector: traffic_protocol_redis::process_request::PublishSelector {
                        ports: ports.clone(),
                        channels,
                        when_message: when_message.clone(),
                    },
                });
            }
            ensure!(
                when_message.is_empty(),
                "process Redis when_message requires PUBLISH"
            );
            let mut exact = vec![];
            let mut patterns = vec![];
            let mut affix = None;
            for key in keys {
                match key {
                    n::NativeKeySelector::Exact { value } => exact.push(value.clone()),
                    n::NativeKeySelector::Numeric { prefix, suffix } => {
                        patterns.push(RedisKeyPatternConfig {
                            prefix: prefix.clone(),
                            suffix: suffix.clone(),
                            numeric_middle: true,
                        })
                    }
                    n::NativeKeySelector::Affix { prefix, suffix } => {
                        ensure!(
                            keys.len() == 1,
                            "unbounded-middle process key cannot mix with another selector"
                        );
                        affix = Some((prefix.clone(), suffix.clone()));
                    }
                }
            }
            let (key_prefix, key_suffix) = affix.unwrap_or_default();
            B::Redis {
                name,
                source_revision,
                source_evidence,
                ports: ports.clone(),
                command: operation.clone(),
                keys: exact,
                key_patterns: patterns,
                key_prefix,
                key_suffix,
                key_templates: key_templates.clone(),
                key_sequence: key_sequence.clone(),
                arguments: arguments.clone(),
                script: script
                    .as_ref()
                    .map(|script| origin_script(&script.contract))
                    .transpose()?,
                trigger_source,
                initial_load_timeout_ms: *initial_load_timeout_ms,
                fields: fields.clone(),
            }
        }
        n::ProcessSelector::Motan { .. } => {
            anyhow::bail!("Motan process-owned dependency rules are disabled")
        }
        #[cfg(any())]
        n::ProcessSelector::Motan {
            group,
            interface,
            method,
        } => B::Motan {
            name,
            source_revision,
            source_evidence,
            group: group.clone(),
            interface_name: interface.clone(),
            method_name: method.clone(),
        },
    })
}

fn mysql(selector: &n::MysqlProcessSelector) -> Result<super::MysqlBackgroundSelector> {
    Ok(super::MysqlBackgroundSelector {
        target_host: selector.resource.endpoint.host.clone(),
        target_port: selector.resource.endpoint.port,
        database: selector
            .resource
            .database
            .as_ref()
            .and_then(Database::name)
            .context("process MySQL database is absent")?
            .into(),
        username: selector
            .resource
            .username
            .clone()
            .context("process MySQL username is absent")?,
        sql: selector.sql.clone(),
        tables: selector.tables.clone(),
        table_patterns: selector.table_patterns.clone(),
        table_series: selector.table_series.clone(),
    })
}

fn origin_source(origin: &n::ApiOrigin) -> Result<super::ApiTriggerSource> {
    let (method, path) = origin
        .api
        .split_once(' ')
        .context("compiled origin API is invalid")?;
    let capture = origin
        .capture
        .iter()
        .map(|(name, capture)| {
            let capture = &capture.contract;
            Ok((
                name.clone(),
                super::ApiTriggerCapture {
                    protocol: super::ApiCaptureProtocol::Mysql,
                    target_host: capture.resource.endpoint.host.clone(),
                    target_port: capture.resource.endpoint.port,
                    database: capture
                        .resource
                        .database
                        .as_ref()
                        .and_then(Database::name)
                        .context("origin capture database is absent")?
                        .into(),
                    username: capture
                        .resource
                        .username
                        .clone()
                        .context("origin capture username is absent")?,
                    operation: super::ApiCaptureOperation::Insert,
                    tables: capture.tables.clone(),
                    table_patterns: capture.table_patterns.clone(),
                    row_match: capture
                        .row_match
                        .iter()
                        .map(|(key, value)| (key.clone(), value.as_json()))
                        .collect(),
                    column: capture.column.clone(),
                },
            ))
        })
        .collect::<Result<_>>()?;
    Ok(super::ApiTriggerSource {
        kind: super::ApiTriggerKind::Api,
        method: method.into(),
        path: path.into(),
        request_body_json: origin
            .request_body
            .iter()
            .map(|(pointer, value)| {
                let value = match value {
                    crate::policy::SourceScalar::Null => serde_json::Value::Null,
                    crate::policy::SourceScalar::Bool(value) => (*value).into(),
                    crate::policy::SourceScalar::Number(value) => value.clone().into(),
                    crate::policy::SourceScalar::String(value) => value.clone().into(),
                };
                (pointer.clone(), value)
            })
            .collect(),
        capture,
    })
}

fn origin_script(script: &n::OriginScript) -> Result<super::ApiTriggerRedisScript> {
    Ok(super::ApiTriggerRedisScript {
        sha1: script.sha1.clone(),
        argv_count: script.argv_count,
        identity_argv_index: script.identity_argv_index,
        keys: script
            .keys
            .iter()
            .map(|key| {
                Ok(match key {
                    n::NativeKeySelector::Exact { value } => RedisKeyPatternConfig {
                        prefix: value.clone(),
                        suffix: String::new(),
                        numeric_middle: false,
                    },
                    n::NativeKeySelector::Numeric { prefix, suffix } => RedisKeyPatternConfig {
                        prefix: prefix.clone(),
                        suffix: suffix.clone(),
                        numeric_middle: true,
                    },
                    n::NativeKeySelector::Affix { .. } => {
                        anyhow::bail!("origin script KEYS support exact or numeric templates only")
                    }
                })
            })
            .collect::<Result<_>>()?,
    })
}

fn proof(value: Option<&crate::policy::Proof>) -> String {
    value
        .map(|value| format!("{}: {}", value.source, value.fact))
        .unwrap_or_default()
}
