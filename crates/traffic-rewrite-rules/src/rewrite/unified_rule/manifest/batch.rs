//! Batch bundles retain the real full execution and all immutable Source inputs.
use super::*;

impl Bundle {
    pub fn load_attribution(source: &Path) -> Result<Self> {
        crate::dependency_index::recording::authenticate(source)?;
        let (recording, scopes) = crate::dependency_index::recording::case_inputs(source)?;
        let mut output = Self {
            inventory_path: None,
            replay_path: PathBuf::new(),
            replay: Value::Null,
            assertions: Value::Null,
            cases: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        };
        output.freeze(&recording.join(crate::dependency::observation::MANIFEST_FILE))?;
        for (case, scope) in scopes {
            let directory = scope
                .parent()
                .context("Source Case has no directory")?
                .to_owned();
            output.freeze(&directory.join("request.json"))?;
            output.freeze(&directory.join("expected-response.json"))?;
            output.cases.insert(case.to_string(), directory);
        }
        Ok(output)
    }

    pub fn load_batch(
        evidence: &crate::e2e_run::BatchRuleEvidence,
        policy_identity: &str,
    ) -> Result<Self> {
        let mut output = Self {
            inventory_path: None,
            replay_path: evidence.report.clone(),
            replay: Value::Null,
            assertions: Value::Null,
            cases: evidence.cases.clone(),
            artifacts: BTreeMap::new(),
        };
        output.replay = output.json(&evidence.report)?;
        output.assertions = output.json(&evidence.assertions)?;
        let aggregate = output.json(&evidence.aggregate)?;
        output.freeze(&evidence.runner_state)?;
        ensure!(
            output.replay["replay_policy"]["fingerprint"] == policy_identity
                && output.assertions["policy_fingerprint"] == policy_identity,
            "batch rule evidence uses a different policy; execute a fresh full session"
        );
        ensure!(
            output.assertions["expected_response"] == "assertions_only"
                && output.assertions["assertion_mode"] == "runner_owned",
            "batch rule evidence must retain genuine runner-owned response assertions"
        );
        let source = fs::canonicalize(&evidence.case_source)?;
        for document in [&output.assertions, &aggregate] {
            let path = document["case_source"]
                .as_str()
                .context("actual batch artifact has no Source selection")?;
            ensure!(
                fs::canonicalize(path)? == source,
                "actual batch artifacts disagree on Source selection"
            );
        }
        for (case, directory) in output.cases.clone() {
            ensure!(
                output.replay["cases"]
                    .as_array()
                    .is_some_and(|cases| cases.iter().any(|item| item["case_id"] == case)),
                "actual batch report omits a Source input"
            );
            output.freeze(&directory.join("request.json"))?;
            output.freeze(&output.dependency_path(&directory)?)?;
            output.primary_response(&case, &directory)?;
        }
        let (recording, _) = crate::dependency_index::recording_files(&source)?;
        output.freeze(&recording.join("recording-run.json"))?;
        output.freeze(&recording.join(crate::dependency::observation::MANIFEST_FILE))?;
        Ok(output)
    }
}
