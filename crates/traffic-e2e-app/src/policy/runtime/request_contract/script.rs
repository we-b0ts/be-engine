//! Explicit script identity and bounded KEYS/ARGV envelopes; never execute Lua.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use super::config::RedisRequestCommand;

impl RedisRequestCommand {
    pub(super) fn validate_script(&self) -> Result<()> {
        let hex = |value: &Option<String>, len| {
            value
                .as_ref()
                .is_some_and(|v| v.len() == len && v.bytes().all(|b| b.is_ascii_hexdigit()))
        };
        ensure!(
            match self.command.as_str() {
                "EVALSHA" => self
                    .script
                    .as_ref()
                    .is_some_and(|s| hex(&s.sha1, 40) && s.sha256.is_none()),
                "EVAL" => self
                    .script
                    .as_ref()
                    .is_some_and(|s| hex(&s.sha256, 64) && s.sha1.is_none()),
                _ => self.script.is_none(),
            },
            "EVALSHA requires script.sha1, EVAL requires script.sha256; other commands cannot select a script"
        );
        Ok(())
    }

    pub(super) fn key<'a>(&self, args: &'a [Vec<u8>]) -> Option<&'a [u8]> {
        args.get(if self.script.is_some() { 2 } else { 0 })
            .map(Vec::as_slice)
    }

    pub(super) fn validate_arguments(&self, args: &[Vec<u8>]) -> Result<()> {
        if self.command == "LSET" {
            ensure!(
                args.len() == 3,
                "LSET requires a key, list index and element"
            );
        }
        if matches!(self.command.as_str(), "SUBSCRIBE" | "UNSUBSCRIBE") {
            ensure!(
                args.len() == 1,
                "subscription identity requires one explicit subject"
            );
        }
        let Some(_) = &self.script else {
            return Ok(());
        };
        ensure!(
            args.len() <= 129,
            "script request exceeds 128 argument indices"
        );
        ensure!(
            self.matches_identity(args),
            "script differs from the selected identity"
        );
        let count = args.get(1).context("script key count is absent")?;
        let count: usize = std::str::from_utf8(count)?.parse()?;
        ensure!(
            (1..=32).contains(&count) && args.len() > count + 2,
            "script requires 1..32 KEYS and at least one ARGV"
        );
        ensure!(
            self.argument_values
                .keys()
                .all(|i| *i >= count + 2 && *i < args.len()),
            "script time selectors must refer only to present ARGV, never KEYS or numkeys"
        );
        Ok(())
    }

    pub(super) fn matches_identity(&self, args: &[Vec<u8>]) -> bool {
        if self.command == "PUBLISH" {
            let Some(json) = args
                .get(1)
                .and_then(|bytes| crate::json_value::parse(bytes))
            else {
                return false;
            };
            return self.argument_values.values().all(|field| match field {
                super::config::ArgumentRule::Json(fields) => fields
                    .json
                    .keys()
                    .all(|p| crate::value_contract::json::pointer_observed(&json, p)),
                _ => false,
            });
        }
        let Some(script) = &self.script else {
            return true;
        };
        let Some(identity) = args.first() else {
            return false;
        };
        if let Some(sha1) = &script.sha1 {
            identity.eq_ignore_ascii_case(sha1.as_bytes())
        } else {
            identity.len() <= 1024 * 1024
                && script.sha256.as_ref().is_some_and(|v| {
                    v.eq_ignore_ascii_case(&format!("{:x}", Sha256::digest(identity)))
                })
        }
    }
}
