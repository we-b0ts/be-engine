//! Complete immutable key lifetimes for metadata-only read/refresh equivalence.
use super::{StorageExchange, normalized_username as normalize_optional, target_matches};
use crate::session_binding::ConnectionScopes;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use traffic_model::{DependencyExchangeOutcome, attribution::DependencyScope as ReplaySource};
use traffic_protocol::connection::Endpoint;

const MAX_BYTES: usize = traffic_value::MAX_VALUE_BYTES;

/// Value recognition, selected metadata and stable-field comparison belong to
/// the installed value implementation. Redis owns only storage lifetimes.
pub trait ValueModel {
    type Value;
    type Fields: PartialEq;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Value>;
    fn fields(&self, value: &Self::Value, clock: DateTime<Utc>) -> Result<Self::Fields>;
    fn same_stable(
        &self,
        before: &Self::Value,
        after: &Self::Value,
        fields: &Self::Fields,
    ) -> Result<bool>;
}

#[derive(Debug)]
pub struct Profile<V, F> {
    pub case: String,
    pub rule: String,
    pub target: Endpoint,
    pub database: i64,
    pub username: Option<String>,
    pub resp_version: u8,
    pub key: Vec<u8>,
    pub lifetimes: Vec<Lifetime<V, F>>,
}

#[derive(Debug)]
pub struct Lifetime<V, F> {
    pub creation: usize,
    pub deletion: Option<usize>,
    pub reads: Vec<usize>,
    pub writes: Vec<usize>,
    pub fields: F,
    pub reference: V,
    pub ttl_args: Vec<Vec<u8>>,
    pub ttl_seconds: u64,
}

impl<V, F> Lifetime<V, F> {
    pub fn eligible(&self) -> bool {
        !self.reads.is_empty() && !self.writes.is_empty()
    }
}

pub fn prepare<E: StorageExchange, V: ValueModel>(
    exchanges: &[E],
    scopes: &ConnectionScopes,
    case: &str,
    rule: &str,
    values: &V,
    seed: &E,
) -> Result<Option<Profile<V::Value, V::Fields>>> {
    let mut profile = Profile {
        case: case.into(),
        rule: rule.into(),
        target: Endpoint {
            host: seed.native_record().target_host.clone(),
            port: seed.native_record().target_port,
        },
        database: seed.native_record().database,
        username: seed.native_record().username.clone(),
        resp_version: seed.native_record().resp_version,
        key: seed
            .arguments()
            .first()
            .context("activity Source key missing")?
            .clone(),
        lifetimes: Vec::new(),
    };
    let mut timeline = Vec::new();
    for (index, e) in exchanges.iter().enumerate().filter(|(_, e)| {
        e.native_record().database == profile.database
            && target_matches(
                &profile.target,
                &e.native_record().target_host,
                e.native_record().target_port,
            )
    }) {
        if !crate::key_access::touches(&e.native_record().command, e.arguments(), &profile.key) {
            continue;
        }
        if super::is_other_ordinary_exchange(case, e) {
            continue;
        }
        ensure!(
            e.source() == ReplaySource::Case
                && e.case_id() == Some(case)
                && !e.explicitly_shared()
                && !e.native_record().cache_snapshot_hit
                && e.native_record().cache_snapshot_rule.is_none()
                && !e.native_record().session_setup
                && e.native_record().run_owner_kind().is_none()
                && e.native_record().outcome == DependencyExchangeOutcome::Response
                && e.native_record().resp_version == profile.resp_version
                && normalize_optional(e.native_record().username.as_deref())
                    == normalize_optional(profile.username.as_deref())
                && !scopes.is_stateful(e),
            "activity refresh requires isolated successful Case inventory without foreign writers, expiry observers or stateful lanes"
        );
        timeline.push((index, e));
    }
    timeline.sort_by_key(|(index, e)| (e.native_record().source_started_at(), *index));
    super::observations::validate_causal_order(&timeline)?;
    let mut current = None;
    let mut bytes = None;
    let mut read_since_write = false;
    let mut known_absent = false;
    for (index, e) in timeline {
        let lifetime_before = current;
        let response = e.response_bytes()?;
        ensure!(
            response.len() <= MAX_BYTES,
            "activity Source response exceeds bounds"
        );
        match e.native_record().command.as_str() {
            "SET" => {
                ensure!(
                    e.arguments().len() == 4
                        && e.arguments()[2].eq_ignore_ascii_case(b"EX")
                        && e.arguments()[3].iter().all(u8::is_ascii_digit)
                        && response == b"+OK\r\n",
                    "activity refresh requires unconditional successful SET with one fixed positive EX TTL"
                );
                let seconds = std::str::from_utf8(&e.arguments()[3])?.parse::<u64>()?;
                ensure!(
                    seconds > 0 && seconds <= i64::MAX as u64 / 1000,
                    "activity TTL exceeds bounds"
                );
                let value = values.decode(&e.arguments()[1])?;
                let clock = e
                    .native_record()
                    .source_started_at()
                    .context("activity Source write clock is absent")?;
                let fields = values.fields(&value, clock)?;
                if let Some(lifetime) = current {
                    let l: &mut Lifetime<V::Value, V::Fields> = &mut profile.lifetimes[lifetime];
                    ensure!(
                        read_since_write,
                        "activity refresh SET has no preceding current-value GET"
                    );
                    ensure!(
                        l.ttl_args == e.arguments()[2..] && l.fields == fields,
                        "activity refresh changes TTL or timestamp format"
                    );
                    ensure!(
                        values.same_stable(&l.reference, &value, &fields)?,
                        "Source activity refresh changes an unselected business field or field set"
                    );
                    l.writes.push(index);
                } else {
                    ensure!(
                        profile.lifetimes.len() < 1024,
                        "activity lifetime limit exceeded"
                    );
                    current = Some(profile.lifetimes.len());
                    profile.lifetimes.push(Lifetime {
                        creation: index,
                        deletion: None,
                        reads: Vec::new(),
                        writes: Vec::new(),
                        fields,
                        reference: value,
                        ttl_args: e.arguments()[2..].to_vec(),
                        ttl_seconds: seconds,
                    });
                }
                bytes = Some(e.arguments()[1].clone());
                read_since_write = false;
                known_absent = false;
            }
            "GET" => {
                ensure!(
                    e.arguments() == [profile.key.clone()],
                    "activity refresh requires a single-key GET"
                );
                if let Some(lifetime) = current {
                    ensure!(
                        response == bulk(bytes.as_deref().context("activity state missing")?),
                        "Source activity GET differs from the latest SET (unknown state or expiration)"
                    );
                    profile.lifetimes[lifetime].reads.push(index);
                    read_since_write = true;
                } else if known_absent {
                    ensure!(
                        response == b"$-1\r\n",
                        "Source activity GET contradicts an owned deletion"
                    );
                }
                // Reads outside a proven lifetime remain ordinary finite calls.
            }
            "DEL" | "UNLINK" => {
                ensure!(
                    e.arguments() == [profile.key.clone()]
                        && (response == b":1\r\n" || response == b":0\r\n"),
                    "activity deletion is not an ordinary successful single-key deletion"
                );
                ensure!(
                    !known_absent || response == b":0\r\n",
                    "Source activity deletion contradicts known absence"
                );
                if let Some(lifetime) = current.take() {
                    ensure!(
                        response == b":1\r\n",
                        "activity deletion contradicts known live state"
                    );
                    profile.lifetimes[lifetime].deletion = Some(index);
                }
                bytes = None;
                read_since_write = false;
                known_absent = true;
            }
            _ => anyhow::bail!(
                "activity key has an unsupported writer, command, script or expiry observer"
            ),
        }
        if let Some(lifetime) = current.or(lifetime_before) {
            let l = &profile.lifetimes[lifetime];
            let first = exchanges[l.creation]
                .native_record()
                .source_started_at()
                .context("activity creation clock missing")?;
            let last = e
                .native_record()
                .timestamp
                .context("activity Source completion clock missing")?;
            ensure!(
                last >= first
                    && last.signed_duration_since(first).num_milliseconds()
                        < (l.ttl_seconds * 1000) as i64,
                "activity Source lifetime reaches its TTL"
            );
        }
    }
    Ok(profile
        .lifetimes
        .iter()
        .any(Lifetime::eligible)
        .then_some(profile))
}

pub fn bulk(bytes: &[u8]) -> Vec<u8> {
    let mut response = format!("${}\r\n", bytes.len()).into_bytes();
    response.extend_from_slice(bytes);
    response.extend_from_slice(b"\r\n");
    response
}
