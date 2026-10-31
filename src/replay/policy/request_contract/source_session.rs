//! Source-only state has explicit equal anchors and no artifact producer.
use super::*;

impl RequestContracts {
    pub(in crate::replay::policy) fn from_source_policy(
        rules: &[ReplayDependencyRule],
        target_root: &Path,
        requests: &BTreeMap<String, (PathBuf, Value)>,
    ) -> Result<Self> {
        let keys = signing_keys::resolve(rules, || Ok(target_root.to_owned()))?;
        let mut state = State::default();
        for (id, (dir, request)) in requests {
            let recorded = request["timestamp"].as_str().map(str::parse).transpose()?;
            let source_body = unified::source_body(request);
            let source_input_error = identity_inputs::capture_error(request, source_body.as_ref());
            state.cases.insert(
                id.clone(),
                CaseAnchor {
                    source_input_error,
                    method: request["method"]
                        .as_str()
                        .context("Source method is absent")?
                        .into(),
                    path: super::super::pattern::uri_path(
                        request["uri"].as_str().context("Source URI is absent")?,
                    ),
                    source_uri: request["uri"]
                        .as_str()
                        .context("Source URI is absent")?
                        .to_owned(),
                    recorded,
                    actual: recorded,
                    dir: dir.clone(),
                    dependencies_path: dir.join("dependencies.jsonl"),
                    source_body,
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
            pre_match_enabled: false,
            hypothesis_context: None,
            hypothesis_journal: None,
            mysql_hypothesis_projections: Arc::default(),
            compiled: None,
            witnesses: None,
            input_origin: Some(derived_inputs::InputOrigin::Root(target_root.to_owned())),
            rules: Arc::new(
                rules
                    .iter()
                    .filter(|rule| is_request_rule(rule))
                    .cloned()
                    .collect(),
            ),
            keys: Arc::new(keys),
            state: Arc::new(Mutex::new(state)),
            identities: Arc::default(),
            time_copies: Arc::default(),
            mysql_automatic: Arc::default(),
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
        for key in self.signing_keys() {
            key.ensure_current()?;
        }
        Ok(())
    }
}
