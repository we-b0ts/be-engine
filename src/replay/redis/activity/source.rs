//! Complete immutable key lifetimes prove metadata-only read/refresh equivalence.
use super::*;

impl RedisReplayState {
    pub(in crate::replay::redis) fn prepare_activity_case(&mut self, case: &str) -> Result<()> {
        if self.activity_refresh.prepared.contains(case) {
            return Ok(());
        }
        let mut profiles = Vec::new();
        let mut seen = BTreeSet::new();
        for seed in self.exchanges.iter().filter(|e| {
            e.source == ReplaySource::Case
                && e.case_id.as_deref() == Some(case)
                && e.record.native.command == "SET"
        }) {
            let target = TargetKey {
                host: seed.record.native.target_host.clone(),
                port: seed.record.native.target_port,
            };
            for compiled in self
                .request_contracts
                .compiled_rules()
                .into_iter()
                .flat_map(|p| &p.native)
            {
                let NativeEffect::RedisActivityRefresh(effect) = &compiled.rule.effect else {
                    continue;
                };
                let rule = &compiled.rule;
                if !self.request_contracts.native_rule_scope_matches(
                    &rule.id,
                    Some(case),
                    Protocol::Redis,
                    &target,
                    Some(&Database::Index(seed.record.native.database)),
                    seed.record.native.username.as_deref(),
                ) || !rule.selector.key.as_ref().is_some_and(|s| {
                    seed.args.first().is_some_and(|k| {
                        crate::replay::policy::native_projection::key(s).matches(k)
                    })
                }) {
                    continue;
                }
                if !seen.insert((
                    target.clone(),
                    seed.record.native.database,
                    normalize_optional(seed.record.native.username.as_deref()),
                    seed.args[0].clone(),
                )) {
                    continue;
                }
                if let Some(profile) = prepare(self, case, &rule.id, &effect.fields, seed)? {
                    profiles.push(profile);
                }
                ensure!(
                    profiles.len() <= MAX_KEYS,
                    "activity refresh exceeds Case key limit"
                );
            }
        }
        ensure!(
            profiles
                .iter()
                .flat_map(|p| &p.lifetimes)
                .filter(|l| l.eligible())
                .map(|l| l.reads.len() + l.writes.len())
                .sum::<usize>()
                <= MAX_CALLS,
            "activity refresh exceeds Source observation bound"
        );
        ensure!(
            profiles
                .iter()
                .flat_map(|p| &p.lifetimes)
                .flat_map(|l| l.reads.iter().chain(&l.writes))
                .all(|&index| self.exchanges[index].observation_rule.is_none()
                    && self.exchanges[index].read_commutation_rule.is_none()),
            "activity refresh overlaps another observation owner"
        );
        // Install no partial permission if any complete Source proof fails.
        for profile in profiles {
            for index in profile
                .lifetimes
                .iter()
                .filter(|l| l.eligible())
                .flat_map(|l| l.reads.iter().chain(&l.writes))
            {
                let e = &mut self.exchanges[*index];
                e.observation_rule = Some(profile.rule.clone());
                self.activity_refresh
                    .owned
                    .entry(case.into())
                    .or_default()
                    .insert((e.record.native.connection_id, e.record.native.sequence));
            }
            self.activity_refresh.profiles.push(profile);
        }
        self.activity_refresh.prepared.insert(case.into());
        Ok(())
    }
}

fn prepare(
    state: &RedisReplayState,
    case: &str,
    rule: &str,
    pointers: &[String],
    seed: &ReplayExchange,
) -> Result<Option<Profile>> {
    let mut profile = Profile {
        case: case.into(),
        rule: rule.into(),
        target: TargetKey {
            host: seed.record.native.target_host.clone(),
            port: seed.record.native.target_port,
        },
        database: seed.record.native.database,
        username: seed.record.native.username.clone(),
        resp_version: seed.record.native.resp_version,
        key: seed.args[0].clone(),
        lifetimes: Vec::new(),
        current: None,
        failed: false,
    };
    let mut timeline = Vec::new();
    for (index, e) in state.exchanges.iter().enumerate().filter(|(_, e)| {
        e.record.native.database == profile.database
            && target_matches(
                &profile.target,
                &e.record.native.target_host,
                e.record.native.target_port,
            )
    }) {
        if !super::super::key_access::touches(&e.record.native.command, &e.args, &profile.key) {
            continue;
        }
        if super::super::case_scope::is_other_ordinary_exchange(case, e) {
            continue;
        }
        ensure!(
            e.source == ReplaySource::Case
                && e.case_id.as_deref() == Some(case)
                && e.shared_rule_id.is_none()
                && !e.reusable_snapshot
                && !e.record.native.cache_snapshot_hit
                && e.record.native.cache_snapshot_rule.is_none()
                && !e.record.native.session_setup
                && e.record.run_owner_kind().is_none()
                && e.record.native.outcome == DependencyExchangeOutcome::Response
                && e.record.native.resp_version == profile.resp_version
                && normalize_optional(e.record.native.username.as_deref())
                    == normalize_optional(profile.username.as_deref())
                && !state.connection_scopes.is_stateful(e),
            "activity refresh requires isolated successful Case inventory without foreign writers, expiry observers or stateful lanes"
        );
        timeline.push((index, e));
    }
    timeline.sort_by_key(|(index, e)| (e.record.started_at(), *index));
    super::super::observations::validate_causal_order(&timeline)?;
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
        match e.record.native.command.as_str() {
            "SET" => {
                ensure!(
                    e.args.len() == 4
                        && e.args[2].eq_ignore_ascii_case(b"EX")
                        && e.args[3].iter().all(u8::is_ascii_digit)
                        && response == b"+OK\r\n",
                    "activity refresh requires unconditional successful SET with one fixed positive EX TTL"
                );
                let seconds = std::str::from_utf8(&e.args[3])?.parse::<u64>()?;
                ensure!(
                    seconds > 0 && seconds <= i64::MAX as u64 / 1000,
                    "activity TTL exceeds bounds"
                );
                let value = value::decode(&e.args[1])?;
                let clock = e
                    .record
                    .started_at()
                    .context("activity Source write clock is absent")?;
                let fields = value::selected(state, &value, pointers, clock)?;
                if let Some(lifetime) = current {
                    let l: &mut Lifetime = &mut profile.lifetimes[lifetime];
                    ensure!(
                        read_since_write,
                        "activity refresh SET has no preceding current-value GET"
                    );
                    ensure!(
                        l.ttl_args == e.args[2..] && l.fields == fields,
                        "activity refresh changes TTL or timestamp format"
                    );
                    ensure!(
                        value::stable(&l.reference, &fields)? == value::stable(&value, &fields)?,
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
                        ttl_args: e.args[2..].to_vec(),
                        ttl_seconds: seconds,
                    });
                }
                bytes = Some(e.args[1].clone());
                read_since_write = false;
                known_absent = false;
            }
            "GET" => {
                ensure!(
                    e.args == [profile.key.clone()],
                    "activity refresh requires a single-key GET"
                );
                if let Some(lifetime) = current {
                    ensure!(
                        response
                            == value::bulk(bytes.as_deref().context("activity state missing")?),
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
                    e.args == [profile.key.clone()]
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
            let first = state.exchanges[l.creation]
                .record
                .started_at()
                .context("activity creation clock missing")?;
            let last = e
                .record
                .native
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
