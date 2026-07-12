use crate::memcached::MemcachedRequest;

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
