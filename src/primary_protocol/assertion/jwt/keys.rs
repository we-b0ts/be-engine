//! Resolve explicitly selected public keys from immutable case dependencies.
use crate::policy::runtime::ResponseJwtKeySource;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) struct VerificationKey {
    pub(crate) bytes: Vec<u8>,
    pub(crate) kid: Option<String>,
    pub(crate) witness: Option<(PathBuf, String)>,
    startup: Option<crate::request_rules::keys::ResolvedSigningKey>,
}

impl VerificationKey {
    #[cfg(test)]
    pub(crate) fn for_test(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.into(),
            kid: None,
            witness: None,
            startup: None,
        }
    }
    pub(crate) fn witnesses(&self) -> impl Iterator<Item = &(PathBuf, String)> {
        self.witness
            .iter()
            .chain(self.startup.iter().flat_map(|key| key.witnesses()))
    }
    pub(crate) fn ensure_current(&self) -> Result<()> {
        if let Some(key) = &self.startup {
            key.ensure_current()?;
        }
        if let Some((path, digest)) = &self.witness {
            ensure!(
                format!("sha256:{:x}", Sha256::digest(std::fs::read(path)?)) == *digest,
                "recorded response key evidence changed"
            );
        }
        Ok(())
    }
    pub(crate) fn resolve(root: &Path, source: &ResponseJwtKeySource, case: &Path) -> Result<Self> {
        Self::resolve_scoped(root, source, case, None)
    }

    pub(crate) fn resolve_scoped(
        root: &Path,
        source: &ResponseJwtKeySource,
        case: &Path,
        identity: Option<&crate::policy::Resource>,
    ) -> Result<Self> {
        if let Some(source) = source.startup() {
            let key = crate::request_rules::keys::ResolvedSigningKey::resolve(root, &source)?;
            return Ok(Self {
                bytes: key.bytes().to_vec(),
                startup: Some(key),
                kid: None,
                witness: None,
            });
        }
        let ResponseJwtKeySource::RecordedMysql {
            host,
            port,
            database,
            sql,
            params,
            column,
            json_pointer,
            kid_pointer,
            algorithm_pointer,
            kid,
        } = source
        else {
            unreachable!()
        };
        let selector = ResponseJwtKeySource::selector_tokens(sql, params)?;
        let path = case.join("dependencies.jsonl");
        let bytes = crate::dependency_index::scoped::read_bytes(&path)?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "JWT dependency evidence is oversized"
        );
        let mut selected = None;
        let mut count = 0;
        for line in bytes.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
            count += 1;
            ensure!(
                count <= 100_000 && line.len() <= 8 * 1024 * 1024,
                "JWT dependency evidence exceeds limits"
            );
            let event =
                crate::json_value::parse(line).context("invalid JWT dependency evidence")?;
            if event["event_type"] != "mysql_exchange"
                || event["target_host"]
                    .as_str()
                    .is_none_or(|h| !h.eq_ignore_ascii_case(host))
                || event["target_port"] != *port
                || event["database"] != *database
                || identity
                    .and_then(|resource| resource.username.as_deref())
                    .is_some_and(|username| event["username"].as_str() != Some(username))
            {
                continue;
            }
            if !matches!(
                event["command"].as_str(),
                Some("COM_QUERY" | "COM_STMT_EXECUTE")
            ) {
                continue;
            }
            let record: crate::protocols::replay::mysql::RecordedMysqlExchange =
                serde_json::from_value(event).context("invalid MySQL key evidence")?;
            let actual = record.sql.as_deref().and_then(|sql| {
                crate::protocols::replay::mysql::sql_match::materialize(
                    sql,
                    record.params.as_deref().unwrap_or_default(),
                )
            });
            if actual.as_ref() != Some(&selector) {
                continue;
            }
            ensure!(
                selected.is_none(),
                "JWT recorded_mysql key selector is ambiguous"
            );
            ensure!(
                record.parse_warnings.is_empty()
                    && record.outcome == crate::DependencyExchangeOutcome::Response
                    && record.response.status == "resultset"
                    && !record.response.rows_truncated
                    && record.response.rows.len() == 1,
                "JWT recorded_mysql key requires one complete successful row"
            );
            let columns = record
                .response
                .columns
                .iter()
                .enumerate()
                .filter(|(_, c)| c.name == *column)
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            ensure!(
                columns.len() == 1,
                "JWT recorded_mysql key column is missing or ambiguous"
            );
            let cell = record.response.rows[0]
                .get(columns[0])
                .context("JWT recorded_mysql key row is incomplete")?;
            let value = cell
                .value
                .as_ref()
                .context("JWT recorded_mysql key JSON is absent")?;
            let document = if let Some(text) = value.as_str() {
                crate::json_value::parse(text.as_bytes()).context("invalid JWT key JSON")?
            } else {
                value.clone()
            };
            ensure!(
                document.pointer(kid_pointer).and_then(Value::as_str) == Some(kid.as_str())
                    && document.pointer(algorithm_pointer).and_then(Value::as_str) == Some("RS256"),
                "JWT recorded_mysql key identity or algorithm differs"
            );
            let public_key = document
                .pointer(json_pointer)
                .and_then(Value::as_str)
                .context("JWT recorded_mysql public key is absent")?;
            ensure!(
                public_key.len() <= 64 * 1024
                    && public_key.starts_with("-----BEGIN PUBLIC KEY-----"),
                "JWT recorded_mysql source requires an RSA public key PEM"
            );
            selected = Some(public_key.as_bytes().to_vec());
        }
        Ok(Self {
            bytes: selected.context("JWT recorded_mysql key selector matched no exchange")?,
            startup: None,
            kid: Some(kid.clone()),
            witness: Some((path, format!("sha256:{:x}", Sha256::digest(&bytes)))),
        })
    }
}
