use crate::cache_protocol::{MemcachedRequest, RedisCommand};

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
                    || subcommand.eq_ignore_ascii_case(b"SETINFO") =>
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
        "SUBSCRIBE"
            | "PSUBSCRIBE"
            | "SSUBSCRIBE"
            | "MONITOR"
            | "CLUSTER"
            | "ACL"
            | "CONFIG"
            | "MIGRATE"
            | "SENTINEL"
    ) || (command.name == "CLIENT"
        && command.args.first().is_some_and(|subcommand| {
            subcommand.eq_ignore_ascii_case(b"TRACKING")
                || subcommand.eq_ignore_ascii_case(b"CACHING")
        }))
}

pub(super) fn memcached_is_unsupported(request: &MemcachedRequest) -> bool {
    matches!(
        request.command.as_str(),
        "mg" | "ms"
            | "md"
            | "ma"
            | "me"
            | "mn"
            | "sasl_list_mechs"
            | "sasl_auth"
            | "sasl_step"
            | "unknown"
    )
}

fn hello_response(version: u8) -> Vec<u8> {
    if version == 3 {
        b"%6\r\n+server\r\n+redis\r\n+version\r\n+7.0.0-replay\r\n+proto\r\n:3\r\n+id\r\n:1\r\n+mode\r\n+standalone\r\n+role\r\n+master\r\n".to_vec()
    } else {
        b"*12\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$12\r\n7.0.0-replay\r\n$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n".to_vec()
    }
}

pub(super) fn binary_error(opcode: u8, opaque: u32) -> Vec<u8> {
    let message = b"no recorded dependency matched";
    let mut response = vec![0_u8; 24];
    response[0] = 0x81;
    response[1] = opcode;
    response[6..8].copy_from_slice(&0x0084_u16.to_be_bytes());
    response[8..12].copy_from_slice(&(message.len() as u32).to_be_bytes());
    response[12..16].copy_from_slice(&opaque.to_be_bytes());
    response.extend_from_slice(message);
    response
}
