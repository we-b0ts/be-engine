//! Frozen primary HTTP evidence and authenticated caller-owned private views.
use super::*;

pub(in crate::rewrite::unified_rule) struct PrimaryResponse {
    pub(in crate::rewrite::unified_rule) source: Value,
    pub(in crate::rewrite::unified_rule) target: Option<Value>,
}

impl Bundle {
    pub(in crate::rewrite::unified_rule) fn request(&mut self, path: &Path) -> Result<Value> {
        let request = self.json(path)?;
        if request.get("private_headers").is_some() {
            self.freeze_private_key(path)?;
        }
        let raw = serde_json::to_vec(&request)?;
        if let Some(decrypted) = crate::request_headers::decrypt_request_bytes(&raw, path)? {
            self.freeze_private_key(path)?;
            return Ok(serde_json::from_slice(&decrypted)?);
        }
        Ok(request)
    }

    fn freeze_private_key(&mut self, path: &Path) -> Result<()> {
        let key = crate::request_headers::project_encryption_key_path(path)
            .context("private rule evidence requires a managed project key")?;
        self.freeze(&key)?;
        self.artifacts[&key].verify()
    }

    fn output_view(&mut self, response: &mut Value, path: &Path) -> Result<()> {
        if response.get("private_interaction_output").is_some() {
            self.freeze_private_key(path)?;
            crate::interaction::private::decrypt_output(response, path)?;
            self.freeze_private_key(path)?;
        }
        Ok(())
    }

    fn primary_view(
        &mut self,
        mut source: Value,
        mut target: Option<Value>,
        expected: &Path,
        actual: Option<&Path>,
    ) -> Result<PrimaryResponse> {
        self.output_view(&mut source, expected)?;
        if let Some((target, path)) = target.as_mut().zip(actual) {
            self.output_view(target, path)?;
        }
        Ok(PrimaryResponse { source, target })
    }

    pub(in crate::rewrite::unified_rule) fn primary_response(
        &mut self,
        case: &str,
        directory: &Path,
    ) -> Result<PrimaryResponse> {
        let summary = self.assertions["cases"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["case_id"] == case))
            .map(|item| item["response"].clone())
            .unwrap_or(Value::Null);
        let recorded = ["expected-response.json", "expected_response.json"]
            .into_iter()
            .map(|name| directory.join(name))
            .find(|path| path.is_file())
            .context("selected Case has no original primary-response oracle")?;
        let expected = summary["expected_response"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| recorded.clone());
        let source = self.json(&expected)?;
        self.freeze(&recorded)?;
        ensure!(
            self.artifacts[&recorded].sha256 == self.artifacts[&expected].sha256,
            "primary Source response does not match the prepared immutable Case"
        );
        ensure!(
            summary.is_null() || summary.is_object(),
            "primary response summary is malformed"
        );
        // The runner publishes detail and the required actual path together.
        // An unavailable response has no summary; deleting only its actual link
        // cannot hide already published Target evidence.
        let actual = if summary.is_null() {
            None
        } else {
            Some(PathBuf::from(
                summary["actual_response"]
                    .as_str()
                    .filter(|path| !path.is_empty())
                    .context("published response summary omits its actual artifact")?,
            ))
        };
        let target = actual.as_deref().map(|path| self.json(path)).transpose()?;
        let Some(detail_path) = summary["detail_report"].as_str() else {
            ensure!(
                actual.is_none(),
                "Target response has no runner-owned assertion detail"
            );
            return self.primary_view(source, target, &expected, actual.as_deref());
        };
        let detail = self.json(Path::new(detail_path))?;
        ensure!(
            crate::verification_progress::fingerprint(&fs::read(detail_path)?)
                == summary["detail_fingerprint"]
                    .as_str()
                    .context("assertion detail fingerprint missing")?
                && detail["case_id"] == case
                && detail["expected_response_path"] == expected.to_string_lossy().as_ref(),
            "response assertion detail identity changed after publication"
        );
        ensure!(
            detail["expected_response_fingerprint"].as_str()
                == Some(crate::verification_progress::fingerprint(&fs::read(&expected)?).as_str()),
            "primary Source response bytes changed after assertion publication"
        );
        if let Some(actual) = &actual {
            ensure!(
                detail["actual_response_path"] == actual.to_string_lossy().as_ref()
                    && detail["actual_response_fingerprint"].as_str()
                        == Some(
                            crate::verification_progress::fingerprint(&fs::read(actual)?).as_str()
                        ),
                "primary Target response bytes changed after assertion publication"
            );
        }
        // BodyCapture/ResponseBody admit only inline utf8/base64 data. Hashing
        // these original JSON files therefore freezes all supported body/frame
        // bytes too; their formats contain no external body-file references.
        self.primary_view(source, target, &expected, actual.as_deref())
    }
}
