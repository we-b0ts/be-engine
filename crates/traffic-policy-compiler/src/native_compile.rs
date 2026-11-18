//! Static native-effect validation and effect-specific semantic identities.
use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use super::{Proof, Protocol, SourceCondition, TimestampFormat, compiler};
use traffic_policy_schema::native::*;

mod activity_refresh;
pub mod codec_binding;
mod http_request;
pub mod ownership;
mod read_back;
mod response;
mod source;
pub mod time;
pub use ownership::*;
use response::{validate_body_field, validate_generated_response, validate_nonce};
use time::{validate_json_time, validate_time};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledNativeRule {
    pub rule: NativeRule,
    pub domain: NativeDomain,
    pub fingerprint: String,
    #[serde(skip)]
    pub execution_plan: std::sync::Arc<crate::plan::RuleExecutionPlan>,
}

pub use traffic_policy_schema::native::NativeDomain;

pub fn compile_definition(
    rule: &NativeRule,
    context: &crate::CompilationContext<'_>,
) -> Result<CompiledNativeRule> {
    let mut normalized = rule.clone();
    source::normalize_process_owner(&mut normalized);
    let rule = &normalized;
    identifier(&rule.id, "rule id")?;
    if let Some(proof) = &rule.proof {
        proof.validate(matches!(rule.effect, NativeEffect::CaptureHttp(_)))?;
    }
    validate_match(&rule.selector)?;
    if let Some(when) = &rule.when {
        ensure!(
            rule.selector.api.is_some(),
            "native when requires an API selector"
        );
        validate_condition(when)?;
    }
    validate_effect(rule, context).with_context(|| format!("invalid native rule {:?}", rule.id))?;
    read_back::validate(rule)?;
    let compiled = CompiledNativeRule {
        rule: rule.clone(),
        domain: rule.effect.domain(),
        fingerprint: compiler::digest("traffic-policy/native-runtime/v1", &semantic_rule(rule)?)?,
        execution_plan: std::sync::Arc::new(super::validate_native_coverage(rule).with_context(
            || {
                format!(
                    "native rule {:?} has an unsupported adapter binding",
                    rule.id
                )
            },
        )?),
    };
    Ok(compiled)
}

/// Values are serialization input only. Runtime dispatch always uses NativeEffect.
pub fn semantic_rule(rule: &NativeRule) -> Result<serde_json::Value> {
    fn strip_proofs(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                let proof_record = fields
                    .get("proof")
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|proof| {
                        proof.get("fact").is_some_and(serde_json::Value::is_string)
                            && (proof.len() == 1
                                || (proof.len() == 2
                                    && proof
                                        .get("source")
                                        .is_some_and(serde_json::Value::is_string)))
                    });
                let proof_owner = (fields.len() == 2 && fields.contains_key("contract"))
                    || (fields.contains_key("id")
                        && fields.contains_key("effect")
                        && fields.contains_key("match"));
                if proof_record && proof_owner {
                    fields.remove("proof");
                }
                for field in fields.values_mut() {
                    strip_proofs(field);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    strip_proofs(value);
                }
            }
            _ => (),
        }
    }
    let mut rule = rule.clone();
    source::normalize_process_owner(&mut rule);
    let mut value = serde_json::to_value(rule)?;
    strip_proofs(&mut value);
    Ok(value)
}

fn validate_match(selector: &NativeMatch) -> Result<()> {
    if let Some(api) = &selector.api {
        api_parts(api)?;
    }
    if let Some(host) = &selector.http_host {
        let authority = host.parse::<hyper::http::uri::Authority>().ok();
        ensure!(host.len() <= 255 && !host.contains('*')
            && authority.is_some_and(|authority|authority.host() == host && authority.port().is_none()),
            "HTTP host selector requires a literal host without port, path or wildcard");
        ensure!(
            selector
                .resource
                .as_ref()
                .is_none_or(|resource| resource.protocol == Protocol::Http
                    && resource
                        .endpoint
                        .host
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(host.trim_end_matches('.')))
                && selector.key.is_none()
                && selector.sql.is_none()
                && selector.tables.is_empty()
                && selector.table_patterns.is_empty()
                && selector.table_series.is_none(),
            "HTTP host selector cannot select a non-HTTP resource, key or SQL"
        );
    }
    if let Some(resource) = &selector.resource {
        resource.endpoint.validate()?;
        match (resource.protocol, &resource.database) {
            (Protocol::Redis, Some(super::Database::Index(index))) => {
                ensure!(*index >= 0, "Redis database must be nonnegative");
            }
            (Protocol::Mysql, Some(super::Database::Name(name))) => text(name, "database", 255)?,
            (Protocol::Redis | Protocol::Mysql, None) => (),
            (Protocol::Http | Protocol::Memcached, None) => (),
            _ => anyhow::bail!("native resource database type does not match its protocol"),
        }
        if let Some(username) = &resource.username {
            ensure!(
                matches!(resource.protocol, Protocol::Redis | Protocol::Mysql),
                "native username identity is supported by Redis and MySQL only"
            );
            text(username, "resource username", 128)?;
        }
        ensure!(
            resource.username.is_none()
                || matches!(resource.protocol, Protocol::Redis | Protocol::Mysql),
            "username identity is supported only by Redis and MySQL"
        );
        ensure!(
            resource.database.is_none()
                || matches!(resource.protocol, Protocol::Redis | Protocol::Mysql),
            "database identity is supported only by Redis and MySQL"
        );
        match resource.protocol {
            Protocol::Redis | Protocol::Memcached => ensure!(
                selector.path.is_none() && selector.sql.is_none(),
                "key protocols cannot select HTTP path or SQL"
            ),
            Protocol::Http => ensure!(
                selector.key.is_none() && selector.sql.is_none(),
                "HTTP cannot select key or SQL"
            ),
            Protocol::Mysql => ensure!(
                selector.key.is_none() && selector.path.is_none(),
                "MySQL cannot select key or HTTP path"
            ),
        }
    }
    if let Some(operation) = &selector.operation {
        text(operation, "operation", 32)?;
    }
    if let Some(key) = &selector.key {
        validate_key(key)?;
    }
    if let Some(path) = &selector.path {
        compiler::validate_path(path)?;
    }
    if let Some(sql) = &selector.sql {
        text(sql, "SQL selector", 8192)?;
    }
    if !selector.tables.is_empty()
        || !selector.table_patterns.is_empty()
        || selector.table_series.is_some()
    {
        ensure!(
            selector
                .resource
                .as_ref()
                .is_some_and(|r| r.protocol == Protocol::Mysql),
            "table selectors require MySQL"
        );
        traffic_protocol_mysql::table_selector::TableMatcher::new(
            &selector.tables,
            &selector.table_patterns,
            selector.table_series.as_ref(),
        )?;
    }
    Ok(())
}

fn validate_effect(rule: &NativeRule, context: &crate::CompilationContext<'_>) -> Result<()> {
    let selector = &rule.selector;
    match &rule.effect {
        NativeEffect::Identity(effect) => validate_identity(rule, effect),
        NativeEffect::RedisSequence(sequence) => validate_sequence(rule, sequence),
        NativeEffect::RedisActivityRefresh(effect) => activity_refresh::validate(rule, effect),
        NativeEffect::RedisReadCommutation(_)
        | NativeEffect::RedisReadObservation(_)
        | NativeEffect::RedisExpiryRefresh(_) => {
            if let NativeEffect::RedisReadObservation(effect) = &rule.effect {
                ensure!(
                    !effect.transient_nil || effect.state_values,
                    "transient nil permission requires the complete key-state contract"
                );
            }
            if selector.resource.is_none() {
                validate_discovered_redis_key(selector)?;
            } else {
                let resource = resource(selector, Protocol::Redis)?;
                ensure!(
                    resource
                        .database
                        .as_ref()
                        .and_then(crate::Database::index)
                        .is_some(),
                    "Redis observations require an explicit numeric Redis database"
                );
            }
            ensure!(
                selector.operation.as_deref()
                    == Some(
                        if matches!(rule.effect, NativeEffect::RedisExpiryRefresh(_)) {
                            "EXPIRE"
                        } else {
                            "GET"
                        }
                    ),
                "observation contract requires its exact GET or EXPIRE operation"
            );
            ensure!(
                selector.key.is_some(),
                "Redis observations require a bounded key selector"
            );
            Ok(())
        }
        NativeEffect::RedisAppendStream => {
            if selector.resource.is_some() {
                resource(selector, Protocol::Redis)?;
                ensure!(
                    selector
                        .resource
                        .as_ref()
                        .and_then(|r| r.database.as_ref())
                        .is_some(),
                    "append stream requires an explicit Redis database"
                );
            } else {
                validate_discovered_redis_key(selector)?;
            }
            ensure!(
                selector.operation.as_deref() == Some("APPEND"),
                "append stream requires operation APPEND"
            );
            ensure!(
                selector.key.is_some(),
                "append stream requires a bounded key selector"
            );
            Ok(())
        }
        NativeEffect::ResponseJwt(effect) => {
            response_scope(rule)?;
            compiler::validate_pointer(&effect.pointer, true)?;
            if let Some(location) = &effect.location {
                ensure!(
                    effect.pointer.is_empty(),
                    "JWT selects either a body pointer or a response header"
                );
                ensure!(
                    effect.expires_at.is_none()
                        && effect.issued_at.is_none()
                        && effect.ttl.is_none(),
                    "header JWT cannot select body companion fields"
                );
                location
                    .header
                    .parse::<hyper::header::HeaderName>()
                    .context("invalid JWT response header")?;
            }
            for nonce in &effect.nonces {
                proven(nonce, |nonce| {
                    validate_nonce(&NonceClaim {
                        pointer: nonce.pointer.clone(),
                        format: nonce.format.clone(),
                    })
                })?;
            }
            match &effect.signing_key {
                ResponseSigningKey::Startup { source } => validate_startup_key(source)?,
                ResponseSigningKey::RecordedPublicKey {
                    resource,
                    sql,
                    params,
                    ..
                } => {
                    ensure!(
                        effect.algorithm == SignatureAlgorithm::RS256,
                        "recorded public keys support RS256 assertions only"
                    );
                    ensure!(
                        resource.protocol == Protocol::Mysql
                            && resource
                                .database
                                .as_ref()
                                .and_then(super::Database::name)
                                .is_some(),
                        "recorded public key requires a MySQL database"
                    );
                    resource.endpoint.validate()?;
                    text(sql, "public-key SQL selector", 8192)?;
                    ensure!(
                        params.len() <= 64 && params.iter().all(|p| !matches!(p, Literal::Bool(_))),
                        "public-key params require at most 64 string, integer or null literals"
                    );
                }
            }
            Ok(())
        }
        NativeEffect::ResponseHeaderDate(effect) => {
            response_scope(rule)?;
            text(&effect.header, "response header", 128)?;
            ensure!(
                matches!(
                    effect.format.as_str(),
                    "%Y-%m-%d" | "%Y%m%d" | "%Y/%m/%d" | "%d-%m-%Y" | "%m-%d-%Y"
                ),
                "unsupported calendar date format"
            );
            offset(&effect.timezone)?;
            Ok(())
        }
        NativeEffect::ResponseGenerated(effect) => {
            response_scope(rule)?;
            ensure!(
                (1..=128).contains(&effect.fields.len()),
                "generated response requires 1..128 fields"
            );
            for (pointer, field) in &effect.fields {
                compiler::validate_pointer(pointer, true)?;
                proven(field, validate_generated_response)?;
            }
            Ok(())
        }
        NativeEffect::ResponseBody(effect) => {
            response_scope(rule)?;
            ensure!(
                effect.fields.len() <= 128,
                "structured response accepts at most 128 fields"
            );
            for field in &effect.fields {
                proven(field, |field| {
                    validate_body_field(effect.codec, field, context)
                })?;
            }
            effect.value_codec(context.codecs)?;
            Ok(())
        }
        NativeEffect::HttpRequest(effect) => http_request::validate(selector, effect),
        NativeEffect::MysqlValues(effect) => {
            resource(selector, Protocol::Mysql)?;
            ensure!(
                selector.sql.is_some(),
                "MySQL value effect requires SQL selector"
            );
            ensure!(
                !effect.params.is_empty() || !effect.values.is_empty(),
                "MySQL value effect has no contract"
            );
            for field in effect.params.values() {
                proven(field, validate_generated_value)?;
            }
            for field in effect.values.values() {
                proven(field, |value| match value {
                    SqlValueContract::Time(time) => validate_time(time),
                    SqlValueContract::Json { fields } => {
                        ensure!(
                            (1..=32).contains(&fields.len()),
                            "SQL JSON requires 1..32 time fields"
                        );
                        for (pointer, time) in fields {
                            compiler::validate_pointer(pointer, true)?;
                            proven(time, |time| validate_json_time(time, pointer))?;
                        }
                        Ok(())
                    }
                })?;
            }
            Ok(())
        }
        NativeEffect::InputJwt(effect) => {
            let mut scope = rule.selector.clone();
            scope.api = None;
            ensure!(
                scope == NativeMatch::default(),
                "input JWT supports only immutable Source API and body conditions"
            );
            ensure!(
                effect.algorithm != SignatureAlgorithm::RS256,
                "inbound JWT execution supports startup HMAC keys"
            );
            validate_startup_key(&effect.signing_key)?;
            match &effect.location {
                InputTokenLocation::BearerHeader { name }
                | InputTokenLocation::RawHeader { name } => {
                    hyper::header::HeaderName::from_bytes(name.as_bytes())?;
                    ensure!(
                        name == &name.to_ascii_lowercase(),
                        "input JWT header must be lowercase"
                    );
                }
                InputTokenLocation::Query { name } => text(name, "input query token", 128)?,
                InputTokenLocation::SocketIoConnect { namespace, pointer } => {
                    crate::validation::socketio_connect(namespace, pointer)?;
                }
            }
            Ok(())
        }
        NativeEffect::InputSignedTimestamp(effect) => {
            let mut scope = rule.selector.clone();
            scope.api = None;
            ensure!(
                rule.selector.api.is_some() && scope == NativeMatch::default(),
                "signed timestamp input requires an immutable Source API scope"
            );
            validate_startup_key(&effect.signing_key)?;
            crate::validation::signed_timestamp(effect)
        }
        NativeEffect::CaptureHttp(_)
        | NativeEffect::CaptureHttpResponse(_)
        | NativeEffect::ProcessOwned(_)
        | NativeEffect::FiniteSharing(_) => source::validate(rule, context),
    }
}

/// These protocol owners discover physical lanes from immutable Source
/// exchanges. Their key namespace must not mix HTTP or SQL selectors.
fn validate_discovered_redis_key(selector: &NativeMatch) -> Result<()> {
    ensure!(
        selector.http_host.is_none()
            && selector.path.is_none()
            && selector.sql.is_none()
            && selector.tables.is_empty()
            && selector.table_patterns.is_empty()
            && selector.table_series.is_none(),
        "key-only Redis behavior cannot select HTTP paths or SQL"
    );
    Ok(())
}

fn validate_identity(rule: &NativeRule, effect: &IdentityEffect) -> Result<()> {
    if traffic_policy_schema::native::is_key_only_read_back(rule) {
        return Ok(());
    }
    let resource = rule
        .selector
        .resource
        .as_ref()
        .context("identity capture requires a resource")?;
    match effect.value_type {
        IdentityType::String => ensure!(
            (1..=32).contains(&effect.references.len()),
            "string identity requires 1..32 explicit reference resources"
        ),
        IdentityType::Integer => ensure!(
            effect.references.is_empty(),
            "integer identity is capture-only; cross-resource integer references have no typed adapter"
        ),
    }
    for reference in &effect.references {
        proven(reference, |reference| {
            reference.resource.endpoint.validate()
        })?;
    }
    match &effect.capture {
        IdentityCapture::MysqlValue { json_pointer, .. } => {
            ensure!(
                resource.protocol == Protocol::Mysql && rule.selector.sql.is_some(),
                "SQL identity capture requires a MySQL SQL selector"
            );
            if let Some(pointer) = json_pointer {
                compiler::validate_pointer(pointer, false)?;
            }
        }
        IdentityCapture::RedisArgument {
            index,
            when,
            json_pointer,
            copies,
            derived_from,
        } => {
            ensure!(
                resource.protocol == Protocol::Redis
                    && rule.selector.operation.is_some()
                    && rule.selector.key.is_some()
                    && *index <= 128,
                "Redis identity capture requires operation, key and bounded argument"
            );
            if let Some(pointer) = json_pointer {
                compiler::validate_pointer(pointer, false)?;
            }
            if let Some(when) = when {
                when.validate(
                    json_pointer
                        .as_deref()
                        .context("conditional Redis identity requires a JSON pointer")?,
                )?;
            }
            for copy in copies {
                if let (Some(when), Some(pointer)) = (when, json_pointer) {
                    ensure!(
                        when.peer_pointer(pointer).as_deref()
                            != Some(copy.contract.pointer.as_str()),
                        "identity copy cannot own its condition discriminator"
                    );
                }
                proven(copy, |copy| {
                    compiler::validate_pointer(&copy.pointer, false)?;
                    text(&copy.template, "identity copy template", 1024)
                })?;
            }
            if let Some(derived) = derived_from {
                proven(derived, |derived| {
                    compiler::validate_pointer(&derived.pointer, false)?;
                    text(&derived.prefix, "derived identity prefix", 128)
                })?;
            }
        }
        IdentityCapture::HttpJson { pointer } => {
            ensure!(
                resource.protocol == Protocol::Http
                    && rule.selector.operation.is_some()
                    && rule.selector.path.is_some(),
                "HTTP identity requires method and path"
            );
            compiler::validate_pointer(pointer, false)?;
        }
        IdentityCapture::HttpPath { segment } => {
            ensure!(
                resource.protocol == Protocol::Http
                    && rule.selector.operation.is_some()
                    && rule.selector.path.is_some(),
                "HTTP identity requires method and path"
            );
            ensure!(
                segment.index < 64 && segment.fields.len() <= 32,
                "path identity exceeds bounds"
            );
            text(&segment.template, "path identity template", 1024)?;
            for field in segment.fields.values() {
                proof(&field.proof)?;
            }
        }
    }
    Ok(())
}

fn validate_sequence(rule: &NativeRule, sequence: &RedisSequenceEffect) -> Result<()> {
    if rule.selector.resource.is_some() {
        resource(&rule.selector, Protocol::Redis)?;
    } else {
        validate_discovered_redis_key(&rule.selector)?;
    }
    ensure!(
        rule.selector.operation.is_none(),
        "an atomic sequence declares operations in its commands"
    );
    ensure!(
        rule.selector.key.is_some(),
        "atomic sequence requires a bounded key selector"
    );
    ensure!(
        (1..=16).contains(&sequence.commands.len()),
        "atomic sequence requires 1..16 commands"
    );
    if let Some(key) = &sequence.key {
        proven(key, validate_key_contract)?;
    }
    let mut operations = BTreeSet::new();
    for command in &sequence.commands {
        text(&command.operation, "sequence operation", 32)?;
        ensure!(
            operations.insert(&command.operation),
            "duplicate sequence operation"
        );
        ensure!(
            command.arguments.len() <= 32
                && (!command.arguments.is_empty() || sequence.key.is_some()),
            "sequence command has no contract or exceeds 32 fields"
        );
        if let Some(script) = &command.script {
            proven(script, |script| {
                ensure!(
                    matches!(command.operation.as_str(), "EVAL" | "EVALSHA"),
                    "script identity requires EVAL/EVALSHA"
                );
                ensure!(
                    script.sha1.is_some() || script.sha256.is_some(),
                    "script identity requires a digest"
                );
                for (hash, size) in script
                    .sha1
                    .iter()
                    .map(|v| (v, 40))
                    .chain(script.sha256.iter().map(|v| (v, 64)))
                {
                    ensure!(
                        hash.len() == size
                            && hash
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                        "script digest must be bounded lowercase hex"
                    );
                }
                Ok(())
            })?;
        }
        for (index, argument) in &command.arguments {
            ensure!(*index <= 128, "sequence argument index exceeds bound");
            proven(argument, |argument| match argument {
                SequenceArgument::Time(time) => validate_time(time),
                SequenceArgument::Json { fields } => {
                    ensure!(
                        (1..=32).contains(&fields.len()),
                        "sequence JSON requires 1..32 fields"
                    );
                    for (pointer, field) in fields {
                        compiler::validate_pointer(pointer, true)?;
                        proven(field, |field| match field {
                            SequenceField::Time(time) => validate_time(time),
                            SequenceField::Identity(reference) => validate_reference(reference),
                            SequenceField::Random {
                                format,
                                length,
                                max_length,
                            } => crate::validation::bounded_random(format, *length, *max_length),
                            SequenceField::Url { query } => {
                                ensure!(
                                    (1..=16).contains(&query.len()),
                                    "URL requires 1..16 selected query fields"
                                );
                                for (name, field) in query {
                                    traffic_policy_value::url_query::validate_name(name)?;
                                    proven(field, |field| match field {
                                        SequenceUrlField::Time(time) => {
                                            ensure!(
                                                matches!(
                                                    time.format,
                                                    TimestampFormat::AmzDate
                                                        | TimestampFormat::Rfc3339
                                                        | TimestampFormat::Iso8601Naive
                                                        | TimestampFormat::SqlDatetime
                                                ),
                                                "URL query times require a textual timestamp format"
                                            );
                                            validate_time(time)
                                        }
                                        SequenceUrlField::UtcDateSegment(segment) => {
                                            ensure!(
                                                segment.index < 64
                                                    && segment.separator.is_ascii_punctuation()
                                                    && !matches!(
                                                        segment.separator,
                                                        '&' | '=' | '?' | '#'
                                                    )
                                                    && matches!(
                                                        query
                                                            .get(&segment.relative_to)
                                                            .map(|v| &v.contract),
                                                        Some(SequenceUrlField::Time(_))
                                                    ),
                                                "URL UTC date segment requires a bounded segment and a selected query time"
                                            );
                                            Ok(())
                                        }
                                        SequenceUrlField::Random { format, length } => {
                                            crate::validation::bounded_random(
                                                format,
                                                Some(*length),
                                                None,
                                            )
                                        }
                                    })?;
                                }
                                Ok(())
                            }
                            SequenceField::Jwt {
                                algorithm,
                                signing_key,
                                relative_to,
                                nonces,
                            } => {
                                ensure!(
                                    *algorithm != SignatureAlgorithm::RS256,
                                    "request JWT requires a startup HMAC key"
                                );
                                validate_startup_key(signing_key)?;
                                ensure!(
                                    matches!(
                                        fields.get(relative_to).map(|f| &f.contract),
                                        Some(SequenceField::Time(NativeTime {
                                            format: TimestampFormat::UnixSeconds,
                                            ..
                                        }))
                                    ),
                                    "JWT relative_to must select a Unix-second time field in the same argument"
                                );
                                for nonce in nonces {
                                    proven(nonce, validate_nonce)?;
                                }
                                Ok(())
                            }
                        })?;
                    }
                    Ok(())
                }
            })?;
        }
    }
    Ok(())
}

fn validate_key_contract(key: &NativeKeyContract) -> Result<()> {
    match key {
        NativeKeyContract::TimeWindow {
            window_seconds,
            separator,
            segment_index,
        } => ensure!(
            (1..=31_536_000).contains(window_seconds)
                && separator.is_ascii_punctuation()
                && !matches!(separator, '{' | '}' | '\\')
                && segment_index.is_none_or(|i| i < 64),
            "invalid key time window"
        ),
        NativeKeyContract::Capture {
            template, format, ..
        } => {
            template_slot(template)?;
            match format {
                KeyIdentityFormat::Hex { bytes } | KeyIdentityFormat::Base64url { bytes } => {
                    ensure!(
                        (1..=256).contains(bytes),
                        "key identity bytes must be 1..256"
                    )
                }
                KeyIdentityFormat::UuidV4 => (),
            }
        }
        NativeKeyContract::Reference(reference) => validate_reference(reference)?,
    }
    Ok(())
}

fn validate_reference(reference: &IdentityReference) -> Result<()> {
    template_slot(&reference.template)
}

fn template_slot(template: &str) -> Result<()> {
    text(template, "identity template", 1024)?;
    ensure!(
        template.matches("{value}").count() == 1,
        "identity template requires exactly one {{value}} slot"
    );
    let rest = template.replace("{value}", "");
    ensure!(
        !rest.contains(['{', '}']),
        "identity template has an undeclared slot"
    );
    Ok(())
}

fn validate_generated_value(value: &GeneratedValue) -> Result<()> {
    match value {
        GeneratedValue::Time(time) => validate_time(time),
        _ => Ok(()),
    }
}

pub fn validate_startup_key(key: &StartupKey) -> Result<()> {
    match key {
        StartupKey::TargetEnv { name } => identifier(name, "startup key environment name"),
        StartupKey::TargetFile { path, field } => {
            ensure!(
                std::path::Path::new(path).is_absolute(),
                "startup key file must be absolute"
            );
            identifier(field, "startup key file field")
        }
    }
}

pub fn validate_key(key: &NativeKeySelector) -> Result<()> {
    match key {
        NativeKeySelector::Exact { value } => text(value, "exact key", 1024),
        NativeKeySelector::Affix { prefix, suffix }
        | NativeKeySelector::Numeric { prefix, suffix } => {
            ensure!(
                !prefix.is_empty() || !suffix.is_empty(),
                "key selector requires fixed affixes"
            );
            ensure!(
                prefix.len() <= 1024
                    && suffix.len() <= 1024
                    && !prefix.contains(['\r', '\n', '\0'])
                    && !suffix.contains(['\r', '\n', '\0']),
                "invalid key affixes"
            );
            Ok(())
        }
    }
}

pub fn resource(selector: &NativeMatch, protocol: Protocol) -> Result<&super::Resource> {
    let resource = selector
        .resource
        .as_ref()
        .context("native effect requires an exact resource")?;
    ensure!(
        resource.protocol == protocol,
        "native effect/resource protocol mismatch"
    );
    Ok(resource)
}

fn response_scope(rule: &NativeRule) -> Result<()> {
    let mut scope = rule.selector.clone();
    scope.api = None;
    ensure!(
        rule.selector.api.is_some() && scope == NativeMatch::default(),
        "assertion effects require only an API selector"
    );
    Ok(())
}

pub fn empty_match(rule: &NativeRule) -> Result<()> {
    ensure!(
        rule.selector == NativeMatch::default() && rule.when.is_none(),
        "effect embeds its own complete scope; outer match/when must be empty"
    );
    Ok(())
}

fn validate_condition(condition: &SourceCondition) -> Result<()> {
    ensure!(
        (1..=16).contains(&condition.request_body_json.len()),
        "Source condition requires 1..16 scalar predicates"
    );
    for pointer in condition.request_body_json.keys() {
        compiler::validate_pointer(pointer, false)?;
    }
    Ok(())
}

pub fn api_parts(api: &str) -> Result<(&str, &str)> {
    compiler::validate_api(api)?;
    let (method, path) = api
        .split_once(' ')
        .context("API selector requires METHOD /path")?;
    Ok((method, path))
}

pub fn proof(proof: &Option<Proof>) -> Result<()> {
    proof
        .as_ref()
        .map(|proof| proof.validate(false))
        .transpose()
        .map(|_| ())
}

pub fn proven<T>(value: &Proven<T>, validate: impl FnOnce(&T) -> Result<()>) -> Result<()> {
    proof(&value.proof)?;
    validate(&value.contract)
}

pub fn identifier(value: &str, name: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
        "{name} requires a bounded ASCII identifier"
    );
    Ok(())
}

pub fn text(value: &str, name: &str, max: usize) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= max && !value.contains(['\r', '\n', '\0']),
        "{name} must be a bounded nonempty single line"
    );
    Ok(())
}

fn offset(value: &str) -> Result<()> {
    ensure!(
        value.is_ascii()
            && value.len() == 6
            && matches!(&value[..1], "+" | "-")
            && value.as_bytes()[3] == b':',
        "UTC offset must be ±HH:MM"
    );
    let hour: u32 = value[1..3].parse()?;
    let minute: u32 = value[4..6].parse()?;
    ensure!(hour <= 23 && minute <= 59, "UTC offset exceeds bounds");
    Ok(())
}
