use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::model::RewriteCommandSpec;

mod model;

pub use model::{
    RewriteCapturePreview, RewriteCaseDependenciesOptions, RewriteCaseDependenciesReport,
    RewriteCaseDependencyProtocolDetail, RewriteCaseDependencyTarget,
    RewriteCaseDependencyTargetSummary, RewriteMemcachedExchangeDetail,
    RewriteMemcachedOperationDetail, RewriteRedisExchangeDetail, RewriteRedisOperationDetail,
};

const MAX_DEPENDENCIES_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEPENDENCY_EVENTS: usize = 100_000;
const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_TARGETS: usize = 512;
const MAX_COMMANDS_PER_TARGET: usize = 256;
const MAX_REPRESENTATIVES: usize = 3;
const MAX_ARGUMENTS_PER_REPRESENTATIVE: usize = 16;
const MAX_PREVIEW_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TargetIdentity {
    protocol: String,
    host: String,
    port: u64,
}

impl TargetIdentity {
    fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn id(&self) -> String {
        let mut hash = Fnv1a::default();
        hash.update(self.protocol.as_bytes());
        hash.update(&[0]);
        hash.update(self.host.as_bytes());
        hash.update(&[0]);
        hash.update(&self.port.to_be_bytes());
        format!("dependency-target-{:016x}", hash.finish())
    }
}

#[derive(Default)]
struct TargetSummaryBuilder {
    event_count: usize,
    commands: BTreeMap<String, usize>,
}

#[derive(Default)]
struct DetailBuilder {
    event_count: usize,
    event_types: BTreeMap<String, usize>,
    commands: BTreeMap<String, usize>,
    redis: BTreeMap<String, RedisOperationBuilder>,
    memcached: BTreeMap<String, MemcachedOperationBuilder>,
}

#[derive(Default)]
struct RedisOperationBuilder {
    count: usize,
    outcomes: BTreeMap<String, usize>,
    response_kinds: BTreeMap<String, usize>,
    representative_exchanges: RepresentativeRedisExchanges,
}

#[derive(Default)]
struct MemcachedOperationBuilder {
    count: usize,
    outcomes: BTreeMap<String, usize>,
    response_statuses: BTreeMap<String, usize>,
    hits: usize,
    misses: usize,
    response_bytes: usize,
    representative_exchanges: RepresentativeMemcachedExchanges,
}

#[derive(Default)]
struct RepresentativeRedisExchanges {
    seen: BTreeSet<String>,
    values: Vec<RewriteRedisExchangeDetail>,
}

impl RepresentativeRedisExchanges {
    fn insert(&mut self, event: &Value, command: &str, args: &[Value]) -> Result<()> {
        if self.values.len() >= MAX_REPRESENTATIVES {
            return Ok(());
        }
        let key_indices = redis_key_indices(command, args.len());
        let keys = key_indices
            .iter()
            .take(MAX_ARGUMENTS_PER_REPRESENTATIVE)
            .filter_map(|index| args.get(*index))
            .map(capture_preview)
            .collect::<Result<Vec<_>>>()?;
        let arguments = args
            .iter()
            .take(MAX_ARGUMENTS_PER_REPRESENTATIVE)
            .map(capture_preview)
            .collect::<Result<Vec<_>>>()?;
        let response = event.get("response");
        let exchange = RewriteRedisExchangeDetail {
            keys,
            omitted_keys: key_indices
                .len()
                .saturating_sub(MAX_ARGUMENTS_PER_REPRESENTATIVE),
            args: arguments,
            omitted_args: args.len().saturating_sub(MAX_ARGUMENTS_PER_REPRESENTATIVE),
            response: response.map(capture_preview).transpose()?,
            response_value: response
                .map(redis_scalar_response_value)
                .transpose()?
                .flatten(),
            response_kind: json_str(event, "response_kind").map(str::to_string),
            outcome: json_str(event, "outcome").map(str::to_string),
        };
        let identity = serde_json::to_string(&exchange)?;
        if self.seen.insert(identity) {
            self.values.push(exchange);
        }
        Ok(())
    }
}

#[derive(Default)]
struct RepresentativeMemcachedExchanges {
    seen: BTreeSet<String>,
    values: Vec<RewriteMemcachedExchangeDetail>,
}

impl RepresentativeMemcachedExchanges {
    fn insert(&mut self, event: &Value, response_bytes: usize) -> Result<()> {
        if self.values.len() >= MAX_REPRESENTATIVES {
            return Ok(());
        }
        let status = json_str(event, "response_status").unwrap_or("unknown");
        let exchange = RewriteMemcachedExchangeDetail {
            key: event
                .get("key")
                .filter(|value| !value.is_null())
                .map(capture_preview)
                .transpose()?,
            response_status: status.to_string(),
            response_classification: memcached_response_classification(event).to_string(),
            response_bytes,
            outcome: json_str(event, "outcome").map(str::to_string),
        };
        let identity = serde_json::to_string(&exchange)?;
        if self.seen.insert(identity) {
            self.values.push(exchange);
        }
        Ok(())
    }
}

pub(super) fn query(
    options: RewriteCaseDependenciesOptions,
) -> Result<RewriteCaseDependenciesReport> {
    let target_root = std::fs::canonicalize(&options.target_root).with_context(|| {
        format!(
            "failed to resolve target root {}",
            options.target_root.display()
        )
    })?;
    let case_dir = resolve_case_dir(&target_root, &options.case_dir)?;
    let dependencies = resolve_dependencies(&case_dir)?;
    match options.target_id {
        Some(target_id) => detail(&case_dir, &dependencies, &target_id),
        None => summary(&target_root, &case_dir, &dependencies),
    }
}

fn summary(
    target_root: &Path,
    case_dir: &Path,
    dependencies: &Path,
) -> Result<RewriteCaseDependenciesReport> {
    let mut total_events = 0_usize;
    let mut ungrouped_events = 0_usize;
    let mut targets = BTreeMap::<TargetIdentity, TargetSummaryBuilder>::new();
    read_events(dependencies, |event| {
        total_events += 1;
        let Some(identity) = target_identity(event) else {
            ungrouped_events += 1;
            return Ok(());
        };
        ensure!(
            targets.len() < MAX_TARGETS || targets.contains_key(&identity),
            "case dependency target count exceeds the supported bound of {MAX_TARGETS}"
        );
        let target = targets.entry(identity).or_default();
        target.event_count += 1;
        if let Some(command) = operation_name(event) {
            ensure!(
                target.commands.len() < MAX_COMMANDS_PER_TARGET
                    || target.commands.contains_key(command),
                "case dependency command count exceeds the supported per-target bound of {MAX_COMMANDS_PER_TARGET}"
            );
            increment(&mut target.commands, command);
        }
        Ok(())
    })?;
    let targeted_events = total_events.saturating_sub(ungrouped_events);
    let targets = targets
        .into_iter()
        .map(|(identity, summary)| {
            let target_id = identity.id();
            let target = identity.target();
            RewriteCaseDependencyTargetSummary {
                target_id: target_id.clone(),
                protocol: identity.protocol,
                target,
                event_count: summary.event_count,
                commands: summary.commands,
                detail_command: detail_command(target_root, case_dir, &target_id),
            }
        })
        .collect::<Vec<_>>();
    Ok(RewriteCaseDependenciesReport::Summary {
        case_dir: case_dir.to_path_buf(),
        total_events,
        targeted_events,
        ungrouped_events,
        targets_total: targets.len(),
        targets,
        next_step: "Execute the selected target's detail_command exactly to inspect bounded representative exchanges that preserve key, argument, and response association."
            .to_string(),
    })
}

fn detail(
    case_dir: &Path,
    dependencies: &Path,
    requested_target_id: &str,
) -> Result<RewriteCaseDependenciesReport> {
    ensure!(
        !requested_target_id.trim().is_empty(),
        "dependency target id must not be empty"
    );
    let mut selected_identity = None::<TargetIdentity>;
    let mut builder = DetailBuilder::default();
    read_events(dependencies, |event| {
        let Some(identity) = target_identity(event) else {
            return Ok(());
        };
        if identity.id() != requested_target_id {
            return Ok(());
        }
        if let Some(selected) = &selected_identity {
            ensure!(
                selected == &identity,
                "dependency target id collision detected"
            );
        } else {
            selected_identity = Some(identity.clone());
        }
        builder.record(event, &identity.protocol)
    })?;
    let identity = selected_identity.with_context(|| {
        format!("case has no dependency target with id {requested_target_id:?}")
    })?;
    let protocol_detail = match identity.protocol.as_str() {
        "redis" => RewriteCaseDependencyProtocolDetail::Redis {
            operations: finish_redis(builder.redis),
        },
        "memcached" => RewriteCaseDependencyProtocolDetail::Memcached {
            operations: finish_memcached(builder.memcached),
        },
        _ => RewriteCaseDependencyProtocolDetail::Generic,
    };
    let target = identity.target();
    Ok(RewriteCaseDependenciesReport::Detail {
        case_dir: case_dir.to_path_buf(),
        target: RewriteCaseDependencyTarget {
            target_id: identity.id(),
            protocol: identity.protocol,
            target,
        },
        event_count: builder.event_count,
        event_types: builder.event_types,
        commands: builder.commands,
        protocol_detail,
    })
}

impl DetailBuilder {
    fn record(&mut self, event: &Value, protocol: &str) -> Result<()> {
        self.event_count += 1;
        increment(
            &mut self.event_types,
            json_str(event, "event_type").unwrap_or("unknown"),
        );
        let Some(command) = operation_name(event) else {
            return Ok(());
        };
        ensure!(
            self.commands.len() < MAX_COMMANDS_PER_TARGET || self.commands.contains_key(command),
            "case dependency command count exceeds the supported per-target bound of {MAX_COMMANDS_PER_TARGET}"
        );
        increment(&mut self.commands, command);
        match protocol {
            "redis" if json_str(event, "event_type") == Some("redis_exchange") => {
                self.redis
                    .entry(command.to_string())
                    .or_default()
                    .record(event)?;
            }
            "memcached" if json_str(event, "event_type") == Some("memcached_exchange") => {
                self.memcached
                    .entry(command.to_string())
                    .or_default()
                    .record(event)?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl RedisOperationBuilder {
    fn record(&mut self, event: &Value) -> Result<()> {
        self.count += 1;
        increment_optional(&mut self.outcomes, json_str(event, "outcome"));
        increment_optional(&mut self.response_kinds, json_str(event, "response_kind"));
        let args = event
            .get("args")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        self.representative_exchanges.insert(
            event,
            json_str(event, "command").unwrap_or_default(),
            args,
        )?;
        Ok(())
    }
}

impl MemcachedOperationBuilder {
    fn record(&mut self, event: &Value) -> Result<()> {
        self.count += 1;
        increment_optional(&mut self.outcomes, json_str(event, "outcome"));
        let status = json_str(event, "response_status").unwrap_or("unknown");
        increment(&mut self.response_statuses, status);
        match memcached_response_classification(event) {
            "hit" => self.hits += 1,
            "miss" => self.misses += 1,
            _ => {}
        }
        let response_bytes = event
            .get("response_frames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|capture| json_u64(capture, "original_len"))
            .filter_map(|value| usize::try_from(value).ok())
            .fold(0_usize, usize::saturating_add);
        self.response_bytes = self.response_bytes.saturating_add(response_bytes);
        self.representative_exchanges
            .insert(event, response_bytes)?;
        Ok(())
    }
}

fn finish_redis(
    operations: BTreeMap<String, RedisOperationBuilder>,
) -> Vec<RewriteRedisOperationDetail> {
    operations
        .into_iter()
        .map(|(command, builder)| {
            let omitted_representative_exchanges = builder
                .count
                .saturating_sub(builder.representative_exchanges.values.len());
            RewriteRedisOperationDetail {
                command,
                count: builder.count,
                outcomes: builder.outcomes,
                response_kinds: builder.response_kinds,
                representative_exchanges: builder.representative_exchanges.values,
                omitted_representative_exchanges,
            }
        })
        .collect()
}

fn finish_memcached(
    operations: BTreeMap<String, MemcachedOperationBuilder>,
) -> Vec<RewriteMemcachedOperationDetail> {
    operations
        .into_iter()
        .map(|(command, builder)| {
            let omitted_representative_exchanges = builder
                .count
                .saturating_sub(builder.representative_exchanges.values.len());
            RewriteMemcachedOperationDetail {
                command,
                count: builder.count,
                outcomes: builder.outcomes,
                response_statuses: builder.response_statuses,
                hits: builder.hits,
                misses: builder.misses,
                response_bytes: builder.response_bytes,
                representative_exchanges: builder.representative_exchanges.values,
                omitted_representative_exchanges,
            }
        })
        .collect()
}

fn memcached_response_classification(event: &Value) -> &'static str {
    let command = json_str(event, "command").unwrap_or_default();
    if !matches!(command, "get" | "gets" | "gat" | "gats") {
        return "not_applicable";
    }
    let status = json_str(event, "response_status").unwrap_or("unknown");
    let no_response = json_bool(event, "no_response").unwrap_or(false);
    let quiet = json_bool(event, "quiet").unwrap_or(false);
    if status == "0" {
        "hit"
    } else if matches!(status, "1" | "END") || (quiet && no_response) {
        "miss"
    } else {
        "unknown"
    }
}

fn resolve_case_dir(target_root: &Path, case_dir: &Path) -> Result<PathBuf> {
    let artifacts =
        std::fs::canonicalize(target_root.join(crate::repository::LOCAL_ARTIFACTS_ROOT))
            .with_context(|| {
                format!(
                    "target repository has no readable {} directory",
                    crate::repository::LOCAL_ARTIFACTS_ROOT
                )
            })?;
    let case_dir = std::fs::canonicalize(case_dir)
        .with_context(|| format!("failed to resolve case directory {}", case_dir.display()))?;
    ensure!(case_dir.is_dir(), "case path must be a directory");
    ensure!(
        case_dir.starts_with(&artifacts),
        "case directory must be inside the target repository {} directory",
        crate::repository::LOCAL_ARTIFACTS_ROOT
    );
    Ok(case_dir)
}

fn resolve_dependencies(case_dir: &Path) -> Result<PathBuf> {
    let dependencies = std::fs::canonicalize(case_dir.join("dependencies.jsonl"))
        .with_context(|| format!("case {} has no dependencies.jsonl", case_dir.display()))?;
    ensure!(
        dependencies.starts_with(case_dir) && dependencies.is_file(),
        "case dependencies must be a regular file inside the case directory"
    );
    let bytes = dependencies.metadata()?.len();
    ensure!(
        bytes <= MAX_DEPENDENCIES_BYTES,
        "case dependencies exceed the supported {} byte bound",
        MAX_DEPENDENCIES_BYTES
    );
    Ok(dependencies)
}

fn read_events(path: &Path, mut visit: impl FnMut(&Value) -> Result<()>) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("failed to open case dependencies {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut count = 0_usize;
    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .with_context(|| format!("failed to read case dependencies {}", path.display()))?;
        if bytes == 0 {
            break;
        }
        ensure!(
            bytes <= MAX_EVENT_BYTES,
            "case dependency event exceeds the supported {} byte bound",
            MAX_EVENT_BYTES
        );
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
        ensure!(
            count <= MAX_DEPENDENCY_EVENTS,
            "case dependency event count exceeds the supported bound of {MAX_DEPENDENCY_EVENTS}"
        );
        let event = serde_json::from_str::<Value>(&line).with_context(|| {
            format!(
                "case dependency event {count} in {} is invalid JSON",
                path.display()
            )
        })?;
        visit(&event)?;
    }
    Ok(())
}

fn target_identity(event: &Value) -> Option<TargetIdentity> {
    let protocol = event_protocol(json_str(event, "event_type")?)?;
    let host = json_str(event, "target_host")?.to_string();
    let port = json_u64(event, "target_port")?;
    Some(TargetIdentity {
        protocol: protocol.to_string(),
        host,
        port,
    })
}

fn event_protocol(event_type: &str) -> Option<&'static str> {
    if event_type.starts_with("redis_") {
        Some("redis")
    } else if event_type.starts_with("memcached_") {
        Some("memcached")
    } else if event_type.starts_with("mysql_") {
        Some("mysql")
    } else if event_type.starts_with("motan_") {
        Some("motan")
    } else if event_type.starts_with("kafka_") {
        Some("kafka")
    } else {
        None
    }
}

fn operation_name(event: &Value) -> Option<&str> {
    json_str(event, "command").or_else(|| json_str(event, "method"))
}

pub(super) fn summary_command(target_root: &Path, case_dir: &Path) -> RewriteCommandSpec {
    let case_dir = case_dir
        .strip_prefix(target_root)
        .unwrap_or(case_dir)
        .display()
        .to_string();
    super::action::command(
        target_root,
        vec!["case".to_string(), "dependencies".to_string(), case_dir],
        Vec::new(),
    )
}

fn detail_command(target_root: &Path, case_dir: &Path, target_id: &str) -> RewriteCommandSpec {
    let mut command = summary_command(target_root, case_dir);
    command.argv.push(target_id.to_string());
    command
}

fn redis_key_indices(command: &str, argument_count: usize) -> Vec<usize> {
    match command.to_ascii_uppercase().as_str() {
        "MGET" | "DEL" | "EXISTS" | "UNLINK" => (0..argument_count).collect(),
        "MSET" => (0..argument_count).step_by(2).collect(),
        "GET" | "SET" | "SETEX" | "PSETEX" | "SETNX" | "GETSET" | "GETDEL" | "GETEX" | "STRLEN"
        | "APPEND" | "INCR" | "INCRBY" | "INCRBYFLOAT" | "DECR" | "DECRBY" | "HGET" | "HSET"
        | "HMGET" | "HMSET" | "HGETALL" | "HDEL" | "HEXISTS" | "HINCRBY" | "HINCRBYFLOAT"
        | "HLEN" | "HKEYS" | "HVALS" | "ZCOUNT" | "ZADD" | "ZRANGE" | "ZREVRANGE"
        | "ZRANGEBYSCORE" | "ZREVRANGEBYSCORE" | "ZSCORE" | "ZREM" | "ZCARD" | "ZINCRBY"
        | "SCARD" | "SISMEMBER" | "SMEMBERS" | "SADD" | "SREM" | "LRANGE" | "LLEN" | "LINDEX"
        | "LPUSH" | "RPUSH" | "LPOP" | "RPOP" | "LSMEXISTS" => {
            (argument_count > 0).then_some(0).into_iter().collect()
        }
        _ => Vec::new(),
    }
}

fn capture_preview(capture: &Value) -> Result<RewriteCapturePreview> {
    let encoding = json_str(capture, "encoding").context("capture has no encoding")?;
    let original_len = json_u64(capture, "original_len")
        .and_then(|value| usize::try_from(value).ok())
        .context("capture has no supported original_len")?;
    let source_truncated = json_bool(capture, "truncated").unwrap_or(false);
    let data = json_str(capture, "data").context("capture has no data")?;
    let bytes = match encoding {
        "base64" => decode_base64_prefix(data)?,
        "utf8" => data.as_bytes()[..data.len().min(MAX_PREVIEW_BYTES)].to_vec(),
        other => anyhow::bail!("unsupported capture encoding {other:?}"),
    };
    let truncated = source_truncated || original_len > bytes.len();
    match std::str::from_utf8(&bytes) {
        Ok(value) => Ok(RewriteCapturePreview {
            encoding: "utf8".to_string(),
            data: value.to_string(),
            original_len,
            truncated,
        }),
        Err(_) => Ok(RewriteCapturePreview {
            encoding: "base64".to_string(),
            data: STANDARD.encode(bytes),
            original_len,
            truncated,
        }),
    }
}

fn redis_scalar_response_value(capture: &Value) -> Result<Option<Value>> {
    let original_len = json_u64(capture, "original_len")
        .and_then(|value| usize::try_from(value).ok())
        .context("capture has no supported original_len")?;
    if original_len > MAX_PREVIEW_BYTES || json_bool(capture, "truncated").unwrap_or(false) {
        return Ok(None);
    }
    let encoding = json_str(capture, "encoding").context("capture has no encoding")?;
    let data = json_str(capture, "data").context("capture has no data")?;
    let bytes = match encoding {
        "base64" => STANDARD
            .decode(data)
            .context("capture data is invalid base64")?,
        "utf8" => data.as_bytes().to_vec(),
        _ => return Ok(None),
    };
    if bytes.len() != original_len {
        return Ok(None);
    }
    Ok(parse_redis_scalar(&bytes))
}

fn parse_redis_scalar(frame: &[u8]) -> Option<Value> {
    if matches!(frame, b"$-1\r\n" | b"*-1\r\n") {
        return Some(Value::Null);
    }
    match frame.first().copied()? {
        b'+' | b'-' => redis_line_payload(frame).map(bytes_value),
        b':' => {
            let value = std::str::from_utf8(redis_line_payload(frame)?).ok()?;
            value.parse::<i64>().ok().map(Value::from)
        }
        b'$' => {
            let header_end = frame.windows(2).position(|window| window == b"\r\n")?;
            let length = std::str::from_utf8(&frame[1..header_end])
                .ok()?
                .parse::<usize>()
                .ok()?;
            let payload_start = header_end + 2;
            let payload_end = payload_start.checked_add(length)?;
            let terminator_end = payload_end.checked_add(2)?;
            (frame.get(payload_end..terminator_end)? == b"\r\n")
                .then(|| bytes_value(&frame[payload_start..payload_end]))
        }
        _ => None,
    }
}

fn redis_line_payload(frame: &[u8]) -> Option<&[u8]> {
    frame.strip_suffix(b"\r\n").and_then(|line| line.get(1..))
}

fn bytes_value(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(value) => Value::String(value.to_string()),
        Err(_) => serde_json::json!({
            "encoding": "base64",
            "data": STANDARD.encode(bytes),
        }),
    }
}

fn decode_base64_prefix(data: &str) -> Result<Vec<u8>> {
    let max_encoded = MAX_PREVIEW_BYTES.div_ceil(3) * 4;
    let mut prefix_len = data.len().min(max_encoded);
    if prefix_len < data.len() {
        prefix_len -= prefix_len % 4;
    }
    let mut decoded = STANDARD
        .decode(&data[..prefix_len])
        .context("capture data is invalid base64")?;
    decoded.truncate(MAX_PREVIEW_BYTES);
    Ok(decoded)
}

fn increment(counts: &mut BTreeMap<String, usize>, value: &str) {
    *counts.entry(value.to_string()).or_default() += 1;
}

fn increment_optional(counts: &mut BTreeMap<String, usize>, value: Option<&str>) {
    if let Some(value) = value {
        increment(counts, value);
    }
}

fn json_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn json_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

#[derive(Default)]
struct Fnv1a(u64);

impl Fnv1a {
    fn update(&mut self, bytes: &[u8]) {
        if self.0 == 0 {
            self.0 = 0xcbf29ce484222325;
        }
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests;
