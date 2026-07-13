use crate::access_policy::OperationClass;

use super::MemcachedRequest;

pub(crate) fn classify_request(request: &MemcachedRequest) -> OperationClass {
    match request.command.as_str() {
        "get" | "gets" | "stat" | "version" => OperationClass::Read,
        "stats" => {
            if request
                .key
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(b"reset"))
            {
                OperationClass::Write
            } else {
                OperationClass::Read
            }
        }
        "noop" | "quit" | "sasl_list_mechs" | "sasl_auth" | "sasl_step" | "mn" => {
            OperationClass::Session
        }
        "set" | "add" | "replace" | "append" | "prepend" | "cas" | "delete" | "incr" | "decr"
        | "increment" | "decrement" | "touch" | "gat" | "gats" | "flush" | "flush_all"
        | "verbosity" | "ms" | "md" | "ma" => OperationClass::Write,
        "mg" => classify_meta_get(request),
        "me" => OperationClass::Read,
        _ => OperationClass::Unknown,
    }
}

fn classify_meta_get(request: &MemcachedRequest) -> OperationClass {
    if request.args.iter().any(|argument| {
        argument
            .first()
            .is_some_and(|flag| matches!(flag.to_ascii_uppercase(), b'N' | b'T'))
    }) {
        OperationClass::Write
    } else {
        OperationClass::Read
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn request(command: &str, args: &[&str]) -> MemcachedRequest {
        MemcachedRequest {
            raw: Bytes::new(),
            command: command.to_string(),
            opcode: None,
            opaque: None,
            key: None,
            args: args
                .iter()
                .map(|argument| argument.as_bytes().to_vec())
                .collect(),
            value: None,
            extras: None,
            cas: None,
            noreply: false,
            quiet: false,
        }
    }

    #[test]
    fn classifies_text_and_binary_command_names() {
        assert_eq!(classify_request(&request("get", &[])), OperationClass::Read);
        assert_eq!(
            classify_request(&request("set", &[])),
            OperationClass::Write
        );
        assert_eq!(
            classify_request(&request("sasl_auth", &[])),
            OperationClass::Session
        );
        assert_eq!(
            classify_request(&request("custom", &[])),
            OperationClass::Unknown
        );
    }

    #[test]
    fn meta_get_with_mutating_flags_is_write() {
        assert_eq!(
            classify_request(&request("mg", &["v"])),
            OperationClass::Read
        );
        assert_eq!(
            classify_request(&request("mg", &["T30"])),
            OperationClass::Write
        );
        assert_eq!(
            classify_request(&request("mg", &["N90"])),
            OperationClass::Write
        );
    }
}
