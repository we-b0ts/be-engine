//! Script command, endpoint and ordered KEYS selectors for Source ownership.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_protocol::evidence::FiniteProcessRequest;

use crate::events::RedisExchangeEvent;

use super::{EVENT_TYPES, capture_bytes, is_finite_response, recorded_args, recorded_port};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptOperation {
    #[serde(rename = "EVAL")]
    Eval,
    #[serde(rename = "EVAL_RO")]
    EvalRo,
}

impl ScriptOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eval => "EVAL",
            Self::EvalRo => "EVAL_RO",
        }
    }
}

pub fn supports_script(operation: &str) -> bool {
    [ScriptOperation::Eval, ScriptOperation::EvalRo]
        .iter()
        .any(|allowed| operation.eq_ignore_ascii_case(allowed.as_str()))
}

pub trait ScriptResource {
    fn matches_endpoint(&self, host: &str, port: u16, db: i64) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptSelector<R> {
    pub operation: ScriptOperation,
    pub resource: R,
    pub script: ScriptDigest,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptDigest {
    pub sha256: String,
}

impl<R> ScriptSelector<R> {
    pub fn validate(&self) -> Result<()> {
        let sha256 = &self.script.sha256;
        ensure!(
            sha256.len() == 64
                && sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "process Redis {} script.sha256 requires a full lowercase SHA-256 digest",
            self.operation.as_str()
        );
        ensure!(
            (1..=32).contains(&self.keys.len())
                && self.keys.iter().all(|key| !key.trim().is_empty()
                    && key.len() <= 1024
                    && !key.contains(['\r', '\n', '\0'])),
            "process Redis {} requires 1..32 ordered exact keys of at most 1024 bytes",
            self.operation.as_str()
        );
        Ok(())
    }
}

impl<R: ScriptResource> ScriptSelector<R> {
    pub fn matches_exchange(&self, exchange: &RedisExchangeEvent) -> bool {
        !exchange.session_setup
            && exchange.replay_safe
            && exchange
                .command
                .eq_ignore_ascii_case(self.operation.as_str())
            && self.resource.matches_endpoint(
                &exchange.target_host,
                exchange.target_port,
                exchange.database,
            )
            && crate::script::matches_eval(
                exchange.args.len(),
                |index| crate::capture::response::complete(exchange.args.get(index)?),
                &self.script.sha256,
                &self.keys,
            )
    }
}

impl<R: ScriptResource + Send + Sync> FiniteProcessRequest for ScriptSelector<R> {
    fn event_types(&self) -> &'static [&'static str] {
        EVENT_TYPES
    }

    fn matches_request(&self, event: &Value) -> bool {
        let (Some(host), Some(port), Some(database), Some(args)) = (
            event["target_host"].as_str(),
            recorded_port(event),
            event["database"].as_i64(),
            recorded_args(event, self.operation.as_str()),
        ) else {
            return false;
        };
        self.resource.matches_endpoint(host, port, database)
            && crate::script::matches_eval(
                args.len(),
                |index| capture_bytes(args.get(index)?),
                &self.script.sha256,
                &self.keys,
            )
    }

    fn matches_evidence(&self, event: &Value) -> Result<bool> {
        if !self.matches_request(event) {
            return Ok(false);
        }
        ensure!(
            event["outcome"] == "response",
            "Source-owned Redis script is unsafe or incomplete"
        );
        ensure!(
            is_finite_response(event),
            "finite process-owned Redis script requires original single-use evidence, not snapshot seeds or hits"
        );
        ensure!(
            event["args"].as_array().is_some_and(|args| args
                .iter()
                .all(|argument| capture_bytes(argument).is_some())),
            "Source Redis script arguments are incomplete"
        );
        let response = capture_bytes(&event["response"])
            .context("Source Redis script response is unavailable")?;
        crate::frame_kind(&Bytes::from(response.into_owned()))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    #[derive(Deserialize)]
    struct TestResource(String);

    impl ScriptResource for TestResource {
        fn matches_endpoint(&self, host: &str, port: u16, db: i64) -> bool {
            host == self.0 && port == 6379 && db == 0
        }
    }

    #[test]
    fn read_only_script_is_an_exact_finite_process_rule() {
        let body = "return redis.call('GET', KEYS[1])";
        let selector: ScriptSelector<TestResource> = serde_json::from_value(json!({
            "operation": "EVAL_RO",
            "resource": "cache.test",
            "script": {"sha256": format!("{:x}", Sha256::digest(body))},
            "keys": ["task:pending"]
        }))
        .unwrap();
        selector.validate().unwrap();
        assert!(supports_script("eval_ro"));
        assert!(!supports_script("EVALSHA_RO"));

        let capture = |data: &str| json!({"encoding": "utf8", "data": data});
        let event = json!({
            "event_type": "redis_exchange", "replay_safe": true,
            "target_host": "cache.test", "target_port": 6379, "database": 0,
            "command": "EVAL_RO", "args": [capture(body), capture("1"), capture("task:pending")],
            "outcome": "response", "response": capture("$1\r\nx\r\n")
        });
        assert!(selector.matches_evidence(&event).unwrap());

        let mut wrong_operation = event.clone();
        wrong_operation["command"] = "EVAL".into();
        assert!(!selector.matches_request(&wrong_operation));
        let mut wrong_keys = event.clone();
        wrong_keys["args"][2] = capture("task:claimed");
        assert!(!selector.matches_request(&wrong_keys));
        let mut incomplete = event;
        incomplete["response"] = capture("$1\r\n");
        assert!(selector.matches_evidence(&incomplete).is_err());
    }
}
