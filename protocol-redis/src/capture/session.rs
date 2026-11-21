//! Native session metadata, credential redaction and successful control transitions.
use crate::RedisCommand;

#[derive(Debug, Clone)]
pub struct CaptureSessionState {
    pub resp_version: u8,
    pub database: i64,
    pub username: Option<String>,
    pub subscriptions: super::subscriptions::Subscriptions,
}

impl CaptureSessionState {
    pub fn snapshot_key(&self, rule: &str, command: &str, args: &[Vec<u8>]) -> Vec<u8> {
        let mut key = Vec::new();
        push_snapshot_component(&mut key, b"redis");
        push_snapshot_component(&mut key, rule.as_bytes());
        key.extend_from_slice(&self.resp_version.to_be_bytes());
        key.extend_from_slice(&self.database.to_be_bytes());
        push_snapshot_component(
            &mut key,
            self.username.as_deref().unwrap_or_default().as_bytes(),
        );
        push_snapshot_component(&mut key, command.as_bytes());
        for argument in args {
            push_snapshot_component(&mut key, argument);
        }
        key
    }

    pub fn apply_successful_setup(
        &mut self,
        command: &RedisCommand,
        response: &[u8],
        sequence: u64,
    ) {
        match command.name.as_str() {
            "HELLO" => {
                if let Some(version) = command
                    .args
                    .first()
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|value| value.parse::<u8>().ok())
                    .filter(|version| matches!(version, 2 | 3))
                {
                    self.resp_version = version;
                }
                for index in 0..command.args.len() {
                    if command.args[index].eq_ignore_ascii_case(b"AUTH")
                        && index + 1 < command.args.len()
                    {
                        self.username = std::str::from_utf8(&command.args[index + 1])
                            .ok()
                            .map(ToOwned::to_owned);
                    }
                }
            }
            "AUTH" => {
                self.username = if command.args.len() >= 2 {
                    std::str::from_utf8(&command.args[0])
                        .ok()
                        .map(ToOwned::to_owned)
                } else {
                    Some("default".to_string())
                };
            }
            "SELECT" => {
                if let Some(database) = command
                    .args
                    .first()
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|value| value.parse::<i64>().ok())
                {
                    self.database = database;
                }
            }
            "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" | "UNSUBSCRIBE" | "PUNSUBSCRIBE"
            | "SUNSUBSCRIBE"
                if self.subscriptions.record_confirmation(command, response) =>
            {
                self.subscriptions.set_anchor(command, sequence);
            }
            _ => {}
        }
    }
}

fn push_snapshot_component(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

pub fn is_terminal_quit(command: &RedisCommand) -> bool {
    command.name == "QUIT"
}

pub fn sanitize_and_classify(command: &RedisCommand) -> (Vec<Vec<u8>>, bool, bool, Vec<String>) {
    let mut args = command.args.clone();
    let mut warnings = Vec::new();
    let session_setup = matches!(command.name.as_str(), "AUTH" | "HELLO" | "SELECT")
        || (command.name == "CLIENT"
            && command.args.first().is_some_and(|subcommand| {
                matches_ignore_ascii_case(subcommand, &[b"SETNAME", b"SETINFO", b"ID", b"GETNAME"])
            }));
    let replay_safe = match command.name.as_str() {
        "AUTH" => {
            if args.len() == 1 {
                args[0] = b"<redacted>".to_vec();
            } else if args.len() >= 2 {
                args[1] = b"<redacted>".to_vec();
            }
            true
        }
        "HELLO" => {
            for index in 0..args.len() {
                if args[index].eq_ignore_ascii_case(b"AUTH") && index + 2 < args.len() {
                    args[index + 2] = b"<redacted>".to_vec();
                }
            }
            true
        }
        "SUBSCRIBE" | "PSUBSCRIBE" | "SSUBSCRIBE" | "UNSUBSCRIBE" | "PUNSUBSCRIBE"
        | "SUNSUBSCRIBE" => {
            if command.args.len() == 1 {
                true
            } else {
                warnings.push(format!(
                    "Redis {} confirmation replay requires exactly one subscription argument",
                    command.name
                ));
                false
            }
        }
        "MONITOR" | "CLUSTER" => {
            warnings.push(format!("Redis {} push mode is unsupported", command.name));
            false
        }
        "CLIENT"
            if command.args.first().is_some_and(|value| {
                matches_ignore_ascii_case(value, &[b"TRACKING", b"CACHING"])
            }) =>
        {
            warnings.push("Redis CLIENT tracking mode is unsupported".to_string());
            false
        }
        "ACL" | "CONFIG" | "MIGRATE" | "SENTINEL" => {
            args.clear();
            warnings.push(format!(
                "Redis {} arguments were omitted because the command may contain credentials",
                command.name
            ));
            false
        }
        _ => true,
    };
    (args, session_setup, replay_safe, warnings)
}

fn matches_ignore_ascii_case(value: &[u8], candidates: &[&[u8]]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests;
