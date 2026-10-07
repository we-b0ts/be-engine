use crate::redis::{RedisCommand, is_pubsub_command};

pub(super) fn redis_builtin(
    command: &RedisCommand,
    resp_version: &mut u8,
    database: &mut i64,
    username: &mut Option<String>,
) -> Option<Vec<u8>> {
    match command.name.as_str() {
        "AUTH" => {
            *username = if command.args.len() >= 2 {
                std::str::from_utf8(&command.args[0])
                    .ok()
                    .map(ToOwned::to_owned)
            } else {
                Some("default".to_string())
            };
            Some(b"+OK\r\n".to_vec())
        }
        "SELECT" => {
            if let Some(selected) = command
                .args
                .first()
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.parse().ok())
            {
                *database = selected;
            }
            Some(b"+OK\r\n".to_vec())
        }
        "HELLO" => {
            let version = command
                .args
                .first()
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(2);
            if !matches!(version, 2 | 3) {
                return Some(b"-NOPROTO unsupported protocol version\r\n".to_vec());
            }
            *resp_version = version;
            for index in 0..command.args.len() {
                if command.args[index].eq_ignore_ascii_case(b"AUTH")
                    && index + 1 < command.args.len()
                {
                    *username = std::str::from_utf8(&command.args[index + 1])
                        .ok()
                        .map(ToOwned::to_owned);
                }
            }
            Some(hello_response(version))
        }
        "CLIENT" => match command.args.first().map(Vec::as_slice) {
            Some(subcommand)
                if subcommand.eq_ignore_ascii_case(b"SETNAME")
                    || crate::redis::is_client_library_info(&command.name, &command.args) =>
            {
                Some(b"+OK\r\n".to_vec())
            }
            Some(subcommand) if subcommand.eq_ignore_ascii_case(b"ID") => Some(b":1\r\n".to_vec()),
            Some(subcommand) if subcommand.eq_ignore_ascii_case(b"GETNAME") => {
                Some(b"$-1\r\n".to_vec())
            }
            _ => None,
        },
        "PING" => Some(match command.args.first() {
            Some(value) => format!("${}\r\n", value.len())
                .into_bytes()
                .into_iter()
                .chain(value.iter().copied())
                .chain(b"\r\n".iter().copied())
                .collect(),
            None => b"+PONG\r\n".to_vec(),
        }),
        "QUIT" => Some(b"+OK\r\n".to_vec()),
        _ => None,
    }
}

pub(super) fn redis_is_builtin(command: &str) -> bool {
    matches!(
        command,
        "AUTH" | "SELECT" | "HELLO" | "CLIENT" | "PING" | "QUIT"
    )
}

pub(super) fn redis_is_unsupported(command: &RedisCommand) -> bool {
    matches!(
        command.name.as_str(),
        "MONITOR" | "CLUSTER" | "ACL" | "CONFIG" | "MIGRATE" | "SENTINEL"
    ) || (is_pubsub_command(&command.name) && command.args.len() != 1)
        || (command.name == "CLIENT"
            && command.args.first().is_some_and(|subcommand| {
                subcommand.eq_ignore_ascii_case(b"TRACKING")
                    || subcommand.eq_ignore_ascii_case(b"CACHING")
            }))
}

fn hello_response(version: u8) -> Vec<u8> {
    if version == 3 {
        b"%6\r\n+server\r\n+redis\r\n+version\r\n+7.0.0-replay\r\n+proto\r\n:3\r\n+id\r\n:1\r\n+mode\r\n+standalone\r\n+role\r\n+master\r\n".to_vec()
    } else {
        b"*12\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$12\r\n7.0.0-replay\r\n$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n".to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_confirmations_are_recorded_exchanges() {
        let subscribe = RedisCommand {
            name: "PSUBSCRIBE".to_string(),
            args: vec![b"events.*".to_vec()],
        };
        assert!(!redis_is_unsupported(&subscribe));

        let multiple = RedisCommand {
            name: "SUBSCRIBE".to_string(),
            args: vec![b"one".to_vec(), b"two".to_vec()],
        };
        assert!(redis_is_unsupported(&multiple));

        let unsubscribe = RedisCommand {
            name: "PUNSUBSCRIBE".to_string(),
            args: vec![b"events.*".to_vec()],
        };
        assert!(!redis_is_unsupported(&unsubscribe));
        assert!(!redis_is_builtin(&unsubscribe.name));

        let unsubscribe_all = RedisCommand {
            name: "UNSUBSCRIBE".to_string(),
            args: vec![],
        };
        assert!(redis_is_unsupported(&unsubscribe_all));
    }
}
