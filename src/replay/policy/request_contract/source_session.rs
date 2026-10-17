//! Source-only state has explicit equal anchors and no artifact producer.
use super::*;

impl RequestContracts {
    pub(in crate::replay::policy) fn from_source_policy(
        rules: &[ReplayDependencyRule],
        target_root: &Path,
        requests: &BTreeMap<String, (PathBuf, Value)>,
    ) -> Result<Self> {
        let mut keys = BTreeMap::new();
        for rule in rules {
            if let Some(super::super::redis_value::RedisSelector::Requests(selector)) = &rule.redis
            {
                for command in &selector.commands {
                    for argument in command.argument_values.values() {
                        if let config::ArgumentRule::Json(json) = argument {
                            for (pointer, field) in &json.json {
                                if let config::JsonField::Jwt(field) = field {
                                    keys.insert(
                                        (rule.id.clone(), pointer.clone()),
                                        crate::request_rules::keys::ResolvedSigningKey::resolve(
                                            target_root,
                                            &field.jwt.signing_key_source,
                                        )?,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        let mut state = State::default();
        for (id, (dir, request)) in requests {
            let recorded = request["timestamp"].as_str().map(str::parse).transpose()?;
            state.cases.insert(
                id.clone(),
                CaseAnchor {
                    method: request["method"]
                        .as_str()
                        .context("Source method is absent")?
                        .into(),
                    path: super::super::pattern::uri_path(
                        request["uri"].as_str().context("Source URI is absent")?,
                    ),
                    recorded,
                    actual: recorded,
                    dir: dir.clone(),
                    source_body: unified::source_body(request),
                    conditions: super::super::case_condition::matching_rule_ids(
                        request,
                        rules.iter().filter_map(|rule| {
                            rule.when.as_ref().map(|when| (rule.id.as_str(), when))
                        }),
                    ),
                },
            );
        }
        Ok(Self {
            compiled: None,
            mysql_selection: Arc::default(),
            witnesses: None,
            rules: Arc::new(
                rules
                    .iter()
                    .filter(|rule| is_request_rule(rule))
                    .cloned()
                    .collect(),
            ),
            keys: Arc::new(keys),
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub(in crate::replay::policy) fn finish_source_session(&self) -> Result<()> {
        ensure!(
            self.state
                .lock()
                .expect("Source contracts")
                .sequences
                .values()
                .all(|sequence| sequence.next == 0),
            "Source atomic sequence is incomplete"
        );
        for key in self.keys.values() {
            key.ensure_current()?;
        }
        Ok(())
    }
}
