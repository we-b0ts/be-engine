//! Explicit test-data migration; production readers never accept this format.
use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::{config as old, dynamic_values as d};
use crate::policy::{self as p, native as n};

mod dependency;
mod feedback;
mod identity;
mod response;
pub(crate) use feedback::*;

pub(crate) fn convert_legacy_policy(
    yaml: &str,
    fixture_root: Option<&Path>,
) -> Result<p::TrafficPolicy> {
    let document: old::ReplayPolicyDocument = serde_yaml::from_str(yaml)?;
    convert_document(document, fixture_root)
}

fn convert_document(
    document: old::ReplayPolicyDocument,
    fixture_root: Option<&Path>,
) -> Result<p::TrafficPolicy> {
    ensure!(
        matches!(document.version, 1 | 3),
        "fixture migration only accepts the explicit version-three DTO"
    );
    let inventory = Inventory::new(&document, fixture_root);
    let mut rules = vec![];
    for (index, rule) in document.dynamic_values.iter().enumerate() {
        rules.push(
            identity::convert(rule, &inventory)
                .with_context(|| format!("legacy fixture identity[{index}] {:?}", rule.id))?
                .into(),
        );
    }
    for (index, rule) in document.dependency_rules.iter().enumerate() {
        rules.extend(
            dependency::convert(rule, &inventory)
                .with_context(|| format!("legacy fixture dependency[{index}] {:?}", rule.id))?,
        );
    }
    rules.extend(response::convert(&document.response_rules, &inventory)?);
    for rule in &document.request_rules.jwt.rules {
        let profile = &document.request_rules.jwt.profiles[&rule.profile];
        let location = if let Some(query) = &rule.query_param {
            n::InputTokenLocation::Query {
                name: query.clone(),
            }
        } else if rule.scheme.as_deref() == Some("raw") {
            n::InputTokenLocation::RawHeader {
                name: rule.header.clone().context("input fixture header absent")?,
            }
        } else {
            n::InputTokenLocation::BearerHeader {
                name: rule.header.clone().context("input fixture header absent")?,
            }
        };
        rules.push(
            native(
                &rule.id,
                n::NativeMatch::default(),
                n::NativeEffect::InputJwt(n::InputJwtEffect {
                    location,
                    algorithm: algorithm(profile.algorithm),
                    signing_key: startup(
                        profile
                            .signing_key_source
                            .as_ref()
                            .context("fixture profile requires its explicit signing source")?,
                    ),
                    time: n::InputTokenTime::PreserveRelative,
                }),
                "synthetic inbound JWT contract",
                None,
            )
            .into(),
        );
    }
    Ok(p::TrafficPolicy {
        format: p::POLICY_FORMAT.into(),
        source_revision: None,
        rules,
    })
}

/// Call at the fixture's file write site; this is not a loader fallback.
pub(crate) fn write_policy(path: impl AsRef<Path>, yaml: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    let yaml = std::str::from_utf8(yaml.as_ref())?;
    let policy = if yaml.contains("traffic-policy/v1") {
        p::parse_policy(yaml)?
    } else {
        convert_legacy_policy(yaml, path.parent())?
    };
    std::fs::write(path, serde_yaml::to_string(&policy)?)?;
    // Fixtures resolving startup keys must declare the same authoritative
    // project.policy binding as production. No parent-depth guess is used by
    // the runtime; this explicitly constructs the synthetic test repository.
    let directory = path.parent().context("fixture policy has no parent")?;
    let root = if directory
        .file_name()
        .is_some_and(|name| name == ".traffic-e2e")
    {
        directory
            .parent()
            .context("fixture policy has no repository")?
    } else {
        directory
    };
    let project = root.join(".traffic-e2e/project.yaml");
    if !project.exists() {
        std::fs::create_dir_all(project.parent().unwrap())?;
        std::fs::write(
            project,
            serde_yaml::to_string(
                &serde_json::json!({"project":{"policy":path.strip_prefix(root)?}}),
            )?,
        )?;
    }
    Ok(())
}

/// Install a domain regression fixture directly. This does not emulate planning
/// or claim that synthetic Source facts authorize a production rule.
pub(crate) fn install_dependency_rule(path: &Path, rule: serde_json::Value) -> Result<()> {
    // Deserialize the original typed DTO directly: JSON map keys encode numeric
    // SQL positions as strings, whereas its YAML representation uses integers.
    let (dependency_rules, dynamic_values) = if rule.get("kind").is_some() {
        let old::BindingEntry::DynamicValue(rule) = serde_json::from_value(rule)?;
        (vec![], vec![rule])
    } else {
        (vec![serde_json::from_value(rule)?], vec![])
    };
    let added = convert_document(
        old::ReplayPolicyDocument {
            version: 3,
            expected_response: old::ExpectedResponseUsage::AssertionsOnly,
            dependency_rules,
            dynamic_values,
            request_rules: Default::default(),
            response_rules: Default::default(),
        },
        path.parent(),
    )?;
    let mut policy = p::parse_policy(&std::fs::read_to_string(path)?)?;
    for added in added.rules {
        policy.rules.retain(|rule| rule.id() != added.id());
        policy.rules.push(added);
    }
    write_policy(path, serde_yaml::to_string(&policy)?)
}

fn proof(fact: &str) -> p::Proof {
    p::Proof {
        source: "test-fixture".into(),
        fact: if fact.trim().is_empty() {
            "Synthetic Source semantics explicitly declared by this regression fixture".into()
        } else {
            fact.trim().replace(['\r', '\n'], " ")
        },
    }
}
fn proven<T>(contract: T, fact: &str) -> n::Proven<T> {
    n::Proven {
        contract,
        proof: proof(fact),
    }
}
fn native(
    id: &str,
    selector: n::NativeMatch,
    effect: n::NativeEffect,
    fact: &str,
    when: Option<p::SourceCondition>,
) -> n::NativeRule {
    n::NativeRule {
        id: id.into(),
        selector,
        effect,
        proof: proof(fact),
        when,
    }
}
fn value(
    id: &str,
    surface: p::Surface,
    selector: p::MatchSpec,
    slot: p::Slot,
    codec: p::Codec,
    contract: BTreeMap<String, p::FieldContract>,
    semantics: ValueSemantics<'_>,
) -> p::Rule {
    p::Rule {
        id: id.into(),
        surface,
        selector,
        slot,
        codec,
        contract,
        proof: proof(semantics.fact),
        when: semantics.when,
        delivery: semantics.delivery,
    }
}
struct ValueSemantics<'a> {
    fact: &'a str,
    when: Option<p::SourceCondition>,
    delivery: Option<p::Delivery>,
}
fn value_semantics(
    fact: &str,
    when: Option<p::SourceCondition>,
    delivery: Option<p::Delivery>,
) -> ValueSemantics<'_> {
    ValueSemantics {
        fact,
        when,
        delivery,
    }
}
fn id(kind: &str, location: &str) -> String {
    format!(
        "fixture-{kind}-{}",
        p::digest("test-fixture/id", &location)
            .unwrap()
            .trim_start_matches("sha256:")
            .get(..16)
            .unwrap()
    )
}
fn api(rule: &old::ReplayDependencyRule) -> Option<String> {
    rule.case_selector
        .as_ref()
        .map(|case| format!("{} {}", case.method, case.path))
}
fn condition(
    when: Option<&super::case_condition::CaseCondition>,
) -> Result<Option<p::SourceCondition>> {
    when.map(|when| {
        Ok(p::SourceCondition {
            request_body_json: when
                .request_body_json
                .iter()
                .map(|(pointer, predicate)| {
                    let scalar = |value: &serde_json::Value| {
                        serde_json::from_value::<p::SourceScalar>(value.clone())
                            .map_err(anyhow::Error::from)
                    };
                    let predicate = match predicate {
                        super::case_condition::JsonCondition::Equals(value) => {
                            p::SourcePredicate::Equals(p::EqualsPredicate {
                                equals: scalar(value)?,
                            })
                        }
                        super::case_condition::JsonCondition::NotEquals(value) => {
                            p::SourcePredicate::NotEquals(p::NotEqualsPredicate {
                                not_equals: scalar(value)?,
                            })
                        }
                    };
                    Ok((pointer.clone(), predicate))
                })
                .collect::<Result<_>>()?,
        })
    })
    .transpose()
}
fn startup(value: &crate::request_rules::keys::SigningKeySource) -> n::StartupKey {
    match value {
        crate::request_rules::keys::SigningKeySource::TargetEnv { name } => {
            n::StartupKey::TargetEnv { name: name.clone() }
        }
        crate::request_rules::keys::SigningKeySource::TargetFile { path, field } => {
            n::StartupKey::TargetFile {
                path: path.to_string_lossy().into(),
                field: field.clone(),
            }
        }
    }
}
fn algorithm(value: crate::request_rules::JwtAlgorithm) -> n::SignatureAlgorithm {
    match value {
        crate::request_rules::JwtAlgorithm::HS256 => n::SignatureAlgorithm::HS256,
        crate::request_rules::JwtAlgorithm::HS384 => n::SignatureAlgorithm::HS384,
        crate::request_rules::JwtAlgorithm::HS512 => n::SignatureAlgorithm::HS512,
    }
}
fn native_key(value: &crate::replay::RedisValueKeySelector) -> n::NativeKeySelector {
    match value {
        crate::replay::RedisValueKeySelector::Exact { value } => n::NativeKeySelector::Exact {
            value: value.clone(),
        },
        crate::replay::RedisValueKeySelector::Affix { prefix, suffix } => {
            n::NativeKeySelector::Affix {
                prefix: prefix.clone(),
                suffix: suffix.clone(),
            }
        }
        crate::replay::RedisValueKeySelector::Numeric { prefix, suffix } => {
            n::NativeKeySelector::Numeric {
                prefix: prefix.clone(),
                suffix: suffix.clone(),
            }
        }
    }
}
fn key(value: &crate::replay::RedisValueKeySelector) -> p::KeySelector {
    match value {
        crate::replay::RedisValueKeySelector::Exact { value } => p::KeySelector {
            exact: Some(value.clone()),
            ..Default::default()
        },
        crate::replay::RedisValueKeySelector::Affix { prefix, suffix } => p::KeySelector {
            prefix: (!prefix.is_empty()).then(|| prefix.clone()),
            suffix: (!suffix.is_empty()).then(|| suffix.clone()),
            ..Default::default()
        },
        crate::replay::RedisValueKeySelector::Numeric { prefix, suffix } => p::KeySelector {
            prefix: (!prefix.is_empty()).then(|| prefix.clone()),
            suffix: (!suffix.is_empty()).then(|| suffix.clone()),
            numeric: true,
            ..Default::default()
        },
    }
}
fn time(value: &old::TimeRule) -> Result<n::NativeTime> {
    let (format, utc_offset) = match value.format.as_deref() {
        None => (p::TimestampFormat::UnixSeconds, None),
        Some("%+" | "%Y-%m-%dT%H:%M:%SZ" | "%Y-%m-%dT%H:%M:%S%.6f+00:00") => {
            (p::TimestampFormat::Rfc3339, None)
        }
        Some("%Y-%m-%dT%H:%M:%S" | "%Y-%m-%dT%H:%M:%S%.f" | "%Y-%m-%dT%H:%M:%S%.6f") => (
            p::TimestampFormat::Iso8601Naive,
            Some(value.timezone.clone().unwrap_or_else(|| "+00:00".into())),
        ),
        Some(
            "%Y-%m-%d %H:%M:%S"
            | "%Y-%m-%d %H:%M:%S%.f"
            | "%Y-%m-%d %H:%M:%S%.6f"
            | "mysql_datetime",
        ) => (
            p::TimestampFormat::SqlDatetime,
            Some(value.timezone.clone().unwrap_or_else(|| "+00:00".into())),
        ),
        Some("%Y%m%dT%H%M%SZ") => (p::TimestampFormat::AmzDate, None),
        format => anyhow::bail!("unsupported test fixture SQL format {format:?}"),
    };
    Ok(n::NativeTime {
        format,
        utc_offset,
        relation: p::TimeRelation::PreserveOffset,
        anchor: p::TimeAnchor::ApiRequestStart,
        clock_group: None,
    })
}
fn request_time(value: &super::request_contract::config::TimeField) -> n::NativeTime {
    use super::request_contract::config::RequestTimestampFormat as F;
    n::NativeTime {
        format: match value.format {
            F::UnixSeconds => p::TimestampFormat::UnixSeconds,
            F::UnixMilliseconds => p::TimestampFormat::UnixMilliseconds,
            F::UnixMicroseconds => p::TimestampFormat::UnixMicroseconds,
            F::Rfc3339 => p::TimestampFormat::Rfc3339,
            F::Iso8601Naive => p::TimestampFormat::Iso8601Naive,
            F::AmzDate => p::TimestampFormat::AmzDate,
            F::SqlDatetime => p::TimestampFormat::SqlDatetime,
        },
        utc_offset: value.utc_offset.clone(),
        relation: p::TimeRelation::PreserveOffset,
        anchor: p::TimeAnchor::ApiRequestStart,
        clock_group: value.clock_group.clone(),
    }
}
fn time_field(value: &n::NativeTime) -> p::FieldContract {
    p::FieldContract::Time {
        format: value.format,
        relation: value.relation,
        anchor: value.anchor,
        utc_offset: value.utc_offset.clone(),
        clock_group: value.clock_group.clone(),
    }
}

struct Inventory {
    resources: Vec<p::Resource>,
    methods: BTreeMap<String, String>,
}

impl Inventory {
    fn new(document: &old::ReplayPolicyDocument, fixture_root: Option<&Path>) -> Self {
        let mut resources = document
            .dependency_rules
            .iter()
            .filter_map(|rule| {
                Some(p::Resource {
                    protocol: match rule.protocol {
                        old::DependencyProtocol::Mysql => p::Protocol::Mysql,
                        old::DependencyProtocol::Redis => p::Protocol::Redis,
                        old::DependencyProtocol::Http => p::Protocol::Http,
                        old::DependencyProtocol::Memcached => p::Protocol::Memcached,
                    },
                    endpoint: p::Endpoint {
                        host: rule.target.host.clone()?,
                        port: rule.target.port?,
                    },
                    database: rule
                        .mysql
                        .as_ref()
                        .and_then(|rule| rule.database.clone())
                        .map(p::Database::Name),
                    username: rule.mysql.as_ref().and_then(|rule| rule.username.clone()),
                })
            })
            .collect::<Vec<_>>();
        for rule in &document.dynamic_values {
            let (protocol, target, database) = match &rule.capture {
                d::DynamicValueCapture::Mysql {
                    target, database, ..
                } => (
                    p::Protocol::Mysql,
                    target,
                    Some(p::Database::Name(database.clone())),
                ),
                d::DynamicValueCapture::Redis {
                    target, database, ..
                } => (
                    p::Protocol::Redis,
                    target,
                    Some(p::Database::Index(*database)),
                ),
                d::DynamicValueCapture::Http { target, .. } => (p::Protocol::Http, target, None),
            };
            resources.push(p::Resource {
                protocol,
                endpoint: p::Endpoint {
                    host: target.host.clone(),
                    port: target.port,
                },
                database,
                username: None,
            });
        }
        let mut methods = BTreeMap::new();
        fn scan(
            path: &Path,
            depth: usize,
            resources: &mut Vec<p::Resource>,
            methods: &mut BTreeMap<String, String>,
        ) {
            if depth > 5 {
                return;
            }
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten().take(1024) {
                let path = entry.path();
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    scan(&path, depth + 1, resources, methods);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if name == "request.json"
                    && let Ok(bytes) = std::fs::read(&path)
                    && let Some(value) = crate::json_value::parse(&bytes)
                    && let (Some(method), Some(uri)) =
                        (value["method"].as_str(), value["uri"].as_str())
                {
                    methods.insert(super::pattern::uri_path(uri), method.into());
                }
                if name != "dependencies.jsonl" {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                for line in bytes.split(|byte| *byte == b'\n') {
                    let Some(value) = crate::json_value::parse(line) else {
                        continue;
                    };
                    let protocol = match value["event_type"].as_str() {
                        Some("mysql_exchange") => p::Protocol::Mysql,
                        Some("redis_exchange") => p::Protocol::Redis,
                        Some("memcached_exchange") => p::Protocol::Memcached,
                        _ => continue,
                    };
                    let (Some(host), Some(port)) = (
                        value["target_host"].as_str(),
                        value["target_port"]
                            .as_u64()
                            .and_then(|value| u16::try_from(value).ok()),
                    ) else {
                        continue;
                    };
                    resources.push(p::Resource {
                        protocol,
                        endpoint: p::Endpoint {
                            host: host.into(),
                            port,
                        },
                        database: if protocol == p::Protocol::Mysql {
                            value["database"]
                                .as_str()
                                .map(|value| p::Database::Name(value.into()))
                        } else {
                            value["database"].as_i64().map(p::Database::Index)
                        },
                        username: value["username"].as_str().map(str::to_owned),
                    });
                }
            }
        }
        if let Some(root) = fixture_root {
            scan(root, 0, &mut resources, &mut methods);
        }
        Self { resources, methods }
    }
    fn resource(
        &self,
        protocol: p::Protocol,
        target: &old::TargetSelector,
        database: Option<p::Database>,
        username: Option<String>,
        port: Option<u16>,
    ) -> Result<p::Resource> {
        let expected_port = target.port.or(port);
        let mut candidates = Vec::<&p::Endpoint>::new();
        for resource in &self.resources {
            if resource.protocol != protocol
                || expected_port.is_some_and(|port| resource.endpoint.port != port)
                || target
                    .host
                    .as_ref()
                    .is_some_and(|host| !resource.endpoint.host.eq_ignore_ascii_case(host))
                || database
                    .as_ref()
                    .is_some_and(|database| resource.database.as_ref() != Some(database))
                || username.as_ref().is_some_and(|username| {
                    resource
                        .username
                        .as_ref()
                        .is_some_and(|actual| actual != username)
                })
            {
                continue;
            }
            if !candidates.contains(&&resource.endpoint) {
                candidates.push(&resource.endpoint);
            }
        }
        let unique = if candidates.len() == 1 {
            candidates.first().copied()
        } else {
            None
        };
        let port = expected_port
            .or_else(|| unique.map(|endpoint| endpoint.port))
            .context("fixture resource port is absent or ambiguous in Source inventory")?;
        let host = target
            .host
            .clone()
            .or_else(|| unique.map(|endpoint| endpoint.host.clone()))
            .context("hostless fixture requires unique complete Source inventory")?;
        Ok(p::Resource {
            protocol,
            endpoint: p::Endpoint { host, port },
            database,
            username,
        })
    }
    fn api(&self, path: &str) -> String {
        format!(
            "{} {}",
            self.methods
                .iter()
                .find(|(actual, _)| super::pattern::path_pattern_matches(path, actual))
                .map(|(_, method)| method.as_str())
                .unwrap_or("GET"),
            path
        )
    }
}

/// Isolated recorded fixtures use the same local AEAD key boundary as production.
pub(crate) struct ManagedFixtureDirectory {
    _root: tempfile::TempDir,
    cases: std::path::PathBuf,
}
impl ManagedFixtureDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.cases
    }
}
pub(crate) fn managed_tempdir() -> Result<ManagedFixtureDirectory> {
    let root = tempfile::tempdir()?;
    let local = root.path().join(".traffic-e2e/local");
    let cases = local.join("cases");
    std::fs::create_dir_all(&cases)?;
    let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap())?;
    std::fs::write(key, crate::request_headers::generate_encryption_key()?)?;
    Ok(ManagedFixtureDirectory { _root: root, cases })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_loader_rejects_all_legacy_versions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.yaml");
        for version in [1, 2, 3] {
            std::fs::write(
                &path,
                format!(
                    "version: {version}\nexpected_response: assertions_only\ndependency_rules: []\n"
                ),
            )
            .unwrap();
            assert!(old::load_replay_policy(&path).is_err());
        }
        write_policy(
            &path,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        assert!(old::load_replay_policy(&path).is_ok());
    }
}
